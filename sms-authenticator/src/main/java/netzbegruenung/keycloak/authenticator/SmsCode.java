package netzbegruenung.keycloak.authenticator;

import org.jboss.logging.Logger;
import org.keycloak.common.util.SecretGenerator;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.UserModel;
import org.keycloak.sessions.AuthenticationSessionModel;

import java.util.Map;

/**
 * Issues the one-time code kept in the auth session notes and rate-limits re-sends.
 * <p>
 * Re-running a challenge (a theme's "resend code" link, a browser refresh, the back
 * button, "try another way") re-sends the still-valid code instead of replacing it: SMS
 * delivery is neither ordered nor reliable, so the user must be able to use whichever
 * message arrives. The expiry is never extended, so one code lives at most {@code ttl};
 * a re-send with less than {@link #MIN_REMAINING_SECONDS} left issues a fresh code instead.
 * <p>
 * A re-send within {@code resendCooldown} seconds of the previous send is ignored: nothing
 * is sent and it does not count as a re-send. The page disables the button for that time.
 * <p>
 * After {@code resendLimit} re-sends within one login attempt (auth session), whether
 * they re-sent the same code or issued a new one, further code requests are blocked for
 * {@code resendBlockDuration} seconds. The block is stored per user in Keycloak's
 * single-use object store, so restarting the login does not lift it; the code already
 * delivered stays valid until its expiry. The counter itself lives in the auth session:
 * a login restart or a new browser tab starts a new attempt with a fresh counter.
 */
final class SmsCode {

	private static final Logger logger = Logger.getLogger(SmsCode.class);

	static final String CODE_NOTE = "code";
	/** Expiry as epoch millis, kept under the historical "ttl" note name. */
	static final String EXPIRY_NOTE = "ttl";
	private static final String RECIPIENT_NOTE = "code_recipient";
	private static final String RESENDS_NOTE = "code_resends";
	private static final String SENT_AT_NOTE = "code_sent_at";
	private static final String BLOCK_KEY_PREFIX = "sms-authenticator.resend-block.";
	private static final String BLOCKED_UNTIL = "blockedUntil";

	static final String RESEND_LIMIT_CONFIG = "resendLimit";
	static final String RESEND_BLOCK_DURATION_CONFIG = "resendBlockDuration";
	static final String RESEND_COOLDOWN_CONFIG = "resendCooldown";
	static final String DEFAULT_LENGTH = "6";
	static final String DEFAULT_TTL = "300";
	static final String DEFAULT_RESEND_LIMIT = "4";
	static final String DEFAULT_RESEND_BLOCK_DURATION = "900";
	static final String DEFAULT_RESEND_COOLDOWN = "60";
	/** Below this remaining lifetime a re-send issues a fresh code rather than a nearly expired one. */
	static final int MIN_REMAINING_SECONDS = 60;

	/**
	 * Outcome of {@link #issue}: a code to send, or nothing because the user is blocked or
	 * still inside the cooldown. {@code resent} is true when the session already had a code,
	 * i.e. this send was requested again by the user and deserves feedback on the page.
	 * {@code nextSendAtMillis} is when the page may offer a re-send again.
	 */
	record Outcome(String code, long expiresAtMillis, long blockedUntilMillis, long nextSendAtMillis, boolean resent) {

		static Outcome issued(String code, long expiresAtMillis, long nextSendAtMillis, boolean resent) {
			return new Outcome(code, expiresAtMillis, 0L, nextSendAtMillis, resent);
		}

		static Outcome blocked(long blockedUntilMillis) {
			return new Outcome(null, 0L, blockedUntilMillis, blockedUntilMillis, false);
		}

		static Outcome coolingDown(long nextSendAtMillis) {
			return new Outcome(null, 0L, 0L, nextSendAtMillis, false);
		}

		boolean blocked() {
			return blockedUntilMillis > 0L;
		}

		boolean coolingDown() {
			return code == null && !blocked();
		}

		/** Seconds (at least 1 while positive) until a re-send is offered again; 0 when it is available. */
		long cooldownSecondsRemaining() {
			long millis = nextSendAtMillis - System.currentTimeMillis();
			return millis <= 0L ? 0L : (millis + 999L) / 1000L;
		}

		/** Whole minutes the code stays valid, for the SMS text. */
		long remainingMinutes() {
			return Math.floorDiv(Math.max(0L, expiresAtMillis - System.currentTimeMillis()) / 1000L, 60L);
		}

		/** Whole minutes (at least 1) until the user may request codes again. */
		long blockedMinutesRemaining() {
			return Math.max(1L, (blockedUntilMillis - System.currentTimeMillis() + 59_999L) / 60_000L);
		}
	}

	private final KeycloakSession session;
	private final int length;
	private final int ttl;
	private final int resendLimit;
	private final int resendBlockDuration;
	private final int resendCooldown;

	SmsCode(KeycloakSession session, Map<String, String> config) {
		this.session = session;
		this.length = intConfig(config, "length", DEFAULT_LENGTH);
		this.ttl = intConfig(config, "ttl", DEFAULT_TTL);
		this.resendLimit = intConfig(config, RESEND_LIMIT_CONFIG, DEFAULT_RESEND_LIMIT);
		this.resendBlockDuration = intConfig(config, RESEND_BLOCK_DURATION_CONFIG, DEFAULT_RESEND_BLOCK_DURATION);
		this.resendCooldown = intConfig(config, RESEND_COOLDOWN_CONFIG, DEFAULT_RESEND_COOLDOWN);
	}

	Outcome issue(AuthenticationSessionModel authSession, UserModel user, String recipient) {
		long now = System.currentTimeMillis();
		long blockedUntil = blockedUntil(user);
		if (blockedUntil > now) {
			return Outcome.blocked(blockedUntil);
		}

		String code = authSession.getAuthNote(CODE_NOTE);
		boolean resent = code != null;
		long expiresAt = parseLongOrZero(authSession.getAuthNote(EXPIRY_NOTE));
		long nextSendAt = parseLongOrZero(authSession.getAuthNote(SENT_AT_NOTE)) + (resendCooldown * 1000L);
		if (resent && nextSendAt > now) {
			logger.debugf("Ignoring SMS code request of user %s inside the %d s cooldown", user.getUsername(), resendCooldown);
			return Outcome.coolingDown(nextSendAt);
		}

		// Every send after the first one in this login attempt counts, whether it re-sends
		// the same code or issues a new one.
		int resends = parseIntOrZero(authSession.getAuthNote(RESENDS_NOTE)) + (resent ? 1 : 0);
		// A non-positive block duration disables blocking: codes are then re-sent without limit.
		if (resends > resendLimit && resendBlockDuration > 0) {
			blockedUntil = block(user, now);
			authSession.setAuthNote(RESENDS_NOTE, "0");
			return Outcome.blocked(blockedUntil);
		}
		authSession.setAuthNote(RESENDS_NOTE, Integer.toString(resends));

		boolean reusable = code != null
			&& expiresAt - now >= MIN_REMAINING_SECONDS * 1000L
			&& recipient.equals(authSession.getAuthNote(RECIPIENT_NOTE));
		if (reusable) {
			logger.debugf("Re-sending SMS code of user %s (re-send %d of %d)", user.getUsername(), resends, resendLimit);
		} else {
			code = SecretGenerator.getInstance().randomString(length, SecretGenerator.DIGITS);
			expiresAt = now + (ttl * 1000L);
			authSession.setAuthNote(CODE_NOTE, code);
			authSession.setAuthNote(EXPIRY_NOTE, Long.toString(expiresAt));
			authSession.setAuthNote(RECIPIENT_NOTE, recipient);
			logger.debugf("Issuing new SMS code of user %s (%s, re-send %d of %d)", user.getUsername(),
				resent ? "previous code expired, about to expire or sent elsewhere" : "first code in this login attempt",
				resends, resendLimit);
		}
		authSession.setAuthNote(SENT_AT_NOTE, Long.toString(now));
		return Outcome.issued(code, expiresAt, now + (resendCooldown * 1000L), resent);
	}

	/** Epoch millis until which the user is blocked, or 0 when not blocked. */
	private long blockedUntil(UserModel user) {
		Map<String, String> block = session.singleUseObjects().get(blockKey(user));
		return block == null ? 0L : parseLongOrZero(block.get(BLOCKED_UNTIL));
	}

	private long block(UserModel user, long now) {
		logger.warnf("Blocking SMS code requests of user %s for %d seconds after %d re-sends",
			user.getUsername(), resendBlockDuration, resendLimit);
		long until = now + (resendBlockDuration * 1000L);
		session.singleUseObjects().put(blockKey(user), resendBlockDuration, Map.of(BLOCKED_UNTIL, Long.toString(until)));
		return until;
	}

	private static String blockKey(UserModel user) {
		return BLOCK_KEY_PREFIX + user.getId();
	}

	/** Reads an int option, falling back to the default when the admin console saved it empty. */
	private static int intConfig(Map<String, String> config, String key, String defaultValue) {
		String value = config.get(key);
		return Integer.parseInt(value == null || value.isBlank() ? defaultValue : value.trim());
	}

	private static int parseIntOrZero(String value) {
		return value == null || value.isBlank() ? 0 : Integer.parseInt(value);
	}

	private static long parseLongOrZero(String value) {
		return value == null || value.isBlank() ? 0L : Long.parseLong(value);
	}
}
