package netzbegruenung.keycloak.authenticator;

import org.jboss.logging.Logger;
import org.keycloak.common.util.SecretGenerator;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.UserModel;
import org.keycloak.sessions.AuthenticationSessionModel;

import java.util.Map;
import java.util.Optional;

/**
 * Issues the one-time code kept in the auth session notes and rate-limits re-sends.
 * <p>
 * Re-running a challenge (a theme's "resend code" link, a browser refresh, the back
 * button, "try another way") re-sends the still-valid code instead of replacing it: SMS
 * delivery is neither ordered nor reliable, so the user must be able to use whichever
 * message arrives. The expiry restarts on every send so the "valid for N minutes" in the
 * SMS text stays true; Keycloak's login timeout still bounds the auth session as a whole.
 * <p>
 * After {@code resendLimit} re-sends of one code, further code requests are blocked for
 * {@code resendBlockDuration} seconds. The block is stored per user in Keycloak's
 * single-use object store, so restarting the login does not lift it; the code already
 * delivered stays valid until its expiry.
 */
final class SmsCode {

	private static final Logger logger = Logger.getLogger(SmsCode.class);

	static final String CODE_NOTE = "code";
	/** Expiry as epoch millis, kept under the historical "ttl" note name. */
	static final String EXPIRY_NOTE = "ttl";
	private static final String RECIPIENT_NOTE = "code_recipient";
	private static final String RESENDS_NOTE = "code_resends";
	private static final String BLOCK_KEY_PREFIX = "sms-authenticator.resend-block.";
	private static final String BLOCKED_UNTIL = "blockedUntil";

	static final String RESEND_LIMIT_CONFIG = "resendLimit";
	static final String RESEND_BLOCK_DURATION_CONFIG = "resendBlockDuration";
	static final String DEFAULT_RESEND_LIMIT = "4";
	static final String DEFAULT_RESEND_BLOCK_DURATION = "900";

	private final KeycloakSession session;
	private final int length;
	private final int ttl;
	private final int resendLimit;
	private final int resendBlockDuration;

	SmsCode(KeycloakSession session, Map<String, String> config) {
		this.session = session;
		this.length = Integer.parseInt(config.get("length"));
		this.ttl = Integer.parseInt(config.get("ttl"));
		this.resendLimit = Integer.parseInt(config.getOrDefault(RESEND_LIMIT_CONFIG, DEFAULT_RESEND_LIMIT));
		this.resendBlockDuration = Integer.parseInt(config.getOrDefault(RESEND_BLOCK_DURATION_CONFIG, DEFAULT_RESEND_BLOCK_DURATION));
	}

	/** Code lifetime in seconds, for the SMS text. */
	int getTtl() {
		return ttl;
	}

	/**
	 * @return the code to send to {@code recipient}, or empty when the user is currently
	 * blocked from requesting codes (see {@link #blockedMinutesRemaining(UserModel)})
	 */
	Optional<String> issue(AuthenticationSessionModel authSession, UserModel user, String recipient) {
		if (blockedUntil(user).isPresent()) {
			return Optional.empty();
		}

		String code = authSession.getAuthNote(CODE_NOTE);
		String expiry = authSession.getAuthNote(EXPIRY_NOTE);
		boolean reusable = code != null
			&& expiry != null
			&& Long.parseLong(expiry) > System.currentTimeMillis()
			&& recipient.equals(authSession.getAuthNote(RECIPIENT_NOTE));
		if (reusable) {
			int resends = parseIntOrZero(authSession.getAuthNote(RESENDS_NOTE)) + 1;
			if (resends > resendLimit) {
				block(user);
				authSession.setAuthNote(RESENDS_NOTE, "0");
				return Optional.empty();
			}
			authSession.setAuthNote(RESENDS_NOTE, Integer.toString(resends));
		} else {
			code = SecretGenerator.getInstance().randomString(length, SecretGenerator.DIGITS);
			authSession.setAuthNote(CODE_NOTE, code);
			authSession.setAuthNote(RECIPIENT_NOTE, recipient);
			authSession.setAuthNote(RESENDS_NOTE, "0");
		}
		authSession.setAuthNote(EXPIRY_NOTE, Long.toString(System.currentTimeMillis() + (ttl * 1000L)));
		return Optional.of(code);
	}

	/** Whole minutes (at least 1) until the user may request codes again; empty when not blocked. */
	Optional<Long> blockedMinutesRemaining(UserModel user) {
		return blockedUntil(user)
			.map(until -> Math.max(1, (until - System.currentTimeMillis() + 59_999) / 60_000));
	}

	private Optional<Long> blockedUntil(UserModel user) {
		Map<String, String> block = session.singleUseObjects().get(blockKey(user));
		return Optional.ofNullable(block).map(notes -> Long.parseLong(notes.get(BLOCKED_UNTIL)));
	}

	private void block(UserModel user) {
		logger.warnf("Blocking SMS code requests of user %s for %d seconds after %d re-sends",
			user.getUsername(), resendBlockDuration, resendLimit);
		long until = System.currentTimeMillis() + (resendBlockDuration * 1000L);
		session.singleUseObjects().put(blockKey(user), resendBlockDuration, Map.of(BLOCKED_UNTIL, Long.toString(until)));
	}

	private static String blockKey(UserModel user) {
		return BLOCK_KEY_PREFIX + user.getId();
	}

	private static int parseIntOrZero(String value) {
		return value == null ? 0 : Integer.parseInt(value);
	}
}
