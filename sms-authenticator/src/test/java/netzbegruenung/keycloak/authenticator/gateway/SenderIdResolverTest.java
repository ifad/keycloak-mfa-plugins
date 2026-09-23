package netzbegruenung.keycloak.authenticator.gateway;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import java.util.HashMap;
import java.util.Map;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

class SenderIdResolverTest {

	private static SenderIdResolver newResolver(Map<String, String> overrides) {
		Map<String, String> config = new HashMap<>();
		config.put("senderId", "global-sender");
		config.put("countrycode", "");
		config.putAll(overrides);
		return new SenderIdResolver(config);
	}

	@Test
	@DisplayName("no overrides configured returns the global sender")
	void noOverridesReturnsGlobalSender() {
		SenderIdResolver resolver = newResolver(Map.of());

		assertFalse(resolver.hasOverrides());
		assertEquals("global-sender", resolver.resolve("+491234567"));
	}

	@Test
	@DisplayName("a US number matches a US,CA region rule")
	void usNumberMatchesRegionRule() {
		SenderIdResolver resolver = newResolver(Map.of("senderIdOverrides", "US,CA=18885551234"));

		assertTrue(resolver.hasOverrides());
		assertEquals("18885551234", resolver.resolve("+12025550123"));
	}

	@Test
	@DisplayName("a Canadian number also matches the US,CA rule, proving region detection is per-number, not per dial code")
	void canadianNumberAlsoMatchesRegionRule() {
		SenderIdResolver resolver = newResolver(Map.of("senderIdOverrides", "US,CA=18885551234"));

		assertEquals("18885551234", resolver.resolve("+14165550123"));
	}

	@Test
	@DisplayName("a German number falls back to the global sender when only US,CA is configured")
	void germanNumberFallsBackToGlobalSender() {
		SenderIdResolver resolver = newResolver(Map.of("senderIdOverrides", "US,CA=18885551234"));

		assertEquals("global-sender", resolver.resolve("+491234567"));
	}

	@Test
	@DisplayName("an ES rule matches a Spanish number")
	void esRuleMatchesSpanishNumber() {
		SenderIdResolver resolver = newResolver(Map.of("senderIdOverrides", "ES=SPAINSENDER"));

		assertEquals("SPAINSENDER", resolver.resolve("+34911234567"));
	}

	@Test
	@DisplayName("a +1= prefix rule matches a matching number")
	void prefixRuleMatchesNumber() {
		SenderIdResolver resolver = newResolver(Map.of("senderIdOverrides", "+1=18885551234"));

		assertEquals("18885551234", resolver.resolve("+12025550123"));
	}

	@Test
	@DisplayName("a region rule wins over a prefix rule for the same number")
	void regionRuleWinsOverPrefixRule() {
		SenderIdResolver resolver = newResolver(Map.of(
			"senderIdOverrides", "+1=PREFIXSENDER##US=REGIONSENDER"
		));

		assertEquals("REGIONSENDER", resolver.resolve("+12025550123"));
	}

	@Test
	@DisplayName("a national number resolves against the configured countrycode default region")
	void nationalNumberResolvesUsingCountryCodeDefaultRegion() {
		SenderIdResolver resolver = newResolver(Map.of(
			"senderIdOverrides", "DE=GERMANSENDER",
			"countrycode", "+49"
		));

		assertEquals("GERMANSENDER", resolver.resolve("0176123456"));
	}

	@Test
	@DisplayName("a national number with no countrycode configured falls back without throwing")
	void nationalNumberWithoutCountryCodeFallsBack() {
		SenderIdResolver resolver = newResolver(Map.of(
			"senderIdOverrides", "DE=GERMANSENDER",
			"countrycode", ""
		));

		assertEquals("global-sender", resolver.resolve("0176123456"));
	}

	@Test
	@DisplayName("malformed entries are skipped and the global sender is used")
	void malformedEntriesAreSkipped() {
		SenderIdResolver resolver = newResolver(Map.of(
			"senderIdOverrides", "US##=18885551234##US,CA=##XX=1888##"
		));

		assertEquals("global-sender", resolver.resolve("+12025550123"));
	}

	@Test
	@DisplayName("case and whitespace in overrides are tolerated")
	void caseAndWhitespaceAreTolerated() {
		SenderIdResolver resolver = newResolver(Map.of("senderIdOverrides", " us , ca = 18885551234 "));

		assertEquals("18885551234", resolver.resolve("+12025550123"));
	}

	@Test
	@DisplayName("a duplicate country keeps the first rule")
	void duplicateCountryKeepsFirstRule() {
		SenderIdResolver resolver = newResolver(Map.of(
			"senderIdOverrides", "US=FIRSTSENDER##US=SECONDSENDER"
		));

		assertEquals("FIRSTSENDER", resolver.resolve("+12025550123"));
	}

	@Test
	@DisplayName("the sender value is stored verbatim, with no + added or removed")
	void senderValueStoredVerbatim() {
		SenderIdResolver resolver = newResolver(Map.of("senderIdOverrides", "US=+18885551234"));

		assertEquals("+18885551234", resolver.resolve("+12025550123"));
	}

	@Test
	@DisplayName("a US number libphonenumber cannot validate still matches the US rule through the +1 calling code")
	void unvalidatableUsNumberStillMatchesRegionRule() {
		SenderIdResolver resolver = newResolver(Map.of("senderIdOverrides", "US,CA=18885551234"));

		// getRegionCodeForNumber returns null here: +1 is shared and this number matches no region.
		assertEquals("18885551234", resolver.resolve("+15555551234"));
	}

	@Test
	@DisplayName("an out-of-range country prefix is ignored instead of throwing")
	void oversizedCountryPrefixDoesNotThrow() {
		Map<String, String> config = new HashMap<>();
		config.put("senderId", "global-sender");
		config.put("countrycode", "+99999999999999999999");
		config.put("senderIdOverrides", "US=18885551234");
		SenderIdResolver resolver = new SenderIdResolver(config);

		assertEquals("global-sender", resolver.resolve("0176123456"));
		assertEquals("18885551234", resolver.resolve("+12025550123"));
	}

	@Test
	@DisplayName("a null country prefix is ignored instead of throwing")
	void nullCountryPrefixDoesNotThrow() {
		Map<String, String> config = new HashMap<>();
		config.put("senderId", "global-sender");
		config.put("countrycode", null);
		config.put("senderIdOverrides", "US=18885551234");
		SenderIdResolver resolver = new SenderIdResolver(config);

		assertEquals("18885551234", resolver.resolve("+12025550123"));
	}
}
