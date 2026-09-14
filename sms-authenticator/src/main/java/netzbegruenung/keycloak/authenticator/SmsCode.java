package netzbegruenung.keycloak.authenticator;

import org.keycloak.common.util.SecretGenerator;
import org.keycloak.sessions.AuthenticationSessionModel;

/**
 * Issues the one-time code kept in the auth session notes. Re-running a challenge (a
 * theme's "resend code" link, a browser refresh, the back button, "try another way")
 * re-sends the still-valid code instead of replacing it: SMS delivery is neither ordered
 * nor reliable, so the user must be able to use whichever message arrives. The expiry
 * restarts on every send so the "valid for N minutes" in the SMS text stays true;
 * Keycloak's login timeout still bounds the auth session as a whole.
 */
final class SmsCode {

	static final String CODE_NOTE = "code";
	/** Expiry as epoch millis, kept under the historical "ttl" note name. */
	static final String EXPIRY_NOTE = "ttl";
	private static final String RECIPIENT_NOTE = "code_recipient";

	private SmsCode() {
	}

	static String issue(AuthenticationSessionModel authSession, String recipient, int length, int ttlSeconds) {
		String code = authSession.getAuthNote(CODE_NOTE);
		String expiry = authSession.getAuthNote(EXPIRY_NOTE);
		boolean reusable = code != null
			&& expiry != null
			&& Long.parseLong(expiry) > System.currentTimeMillis()
			&& recipient.equals(authSession.getAuthNote(RECIPIENT_NOTE));
		if (!reusable) {
			code = SecretGenerator.getInstance().randomString(length, SecretGenerator.DIGITS);
			authSession.setAuthNote(CODE_NOTE, code);
			authSession.setAuthNote(RECIPIENT_NOTE, recipient);
		}
		authSession.setAuthNote(EXPIRY_NOTE, Long.toString(System.currentTimeMillis() + (ttlSeconds * 1000L)));
		return code;
	}
}
