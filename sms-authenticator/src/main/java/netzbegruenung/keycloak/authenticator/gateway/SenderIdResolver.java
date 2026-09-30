/*
 * Copyright 2016 Red Hat, Inc. and/or its affiliates
 * and other contributors as indicated by the @author tags.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 *
 * @author Niko Köbler, https://www.n-k.de, @dasniko
 * @author Netzbegruenung e.V.
 * @author verdigado eG
 */

package netzbegruenung.keycloak.authenticator.gateway;

import com.google.i18n.phonenumbers.NumberParseException;
import com.google.i18n.phonenumbers.PhoneNumberUtil;
import com.google.i18n.phonenumbers.Phonenumber;
import org.jboss.logging.Logger;

import java.util.ArrayList;
import java.util.Collections;
import java.util.Comparator;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Set;
import java.util.concurrent.ConcurrentHashMap;
import java.util.regex.Pattern;

/**
 * Picks the sender ID for a destination number.
 *
 * Some networks only accept a registered number as the sender: Vonage drops SMS to the US and
 * Canada that are sent from an alphanumeric sender ID instead of a toll-free number. The
 * {@code senderIdOverrides} config holds one rule per entry, {@code <countries>=<sender>}, where
 * the countries are ISO 3166-1 alpha-2 codes or {@code +<digits>} dialling prefixes. Country rules
 * are checked before prefix rules, and the longest prefix wins; without a match the global
 * {@code senderId} is used.
 *
 * Every failure mode here falls back to the global sender ID: a misconfigured rule must not stop
 * an SMS from being sent.
 */
class SenderIdResolver {

	static final String OVERRIDES_CONFIG = "senderIdOverrides";

	private static final Logger logger = Logger.getLogger(SenderIdResolver.class);
	// Keycloak joins multivalued config with "##"; line breaks are accepted for hand-edited imports.
	private static final Pattern ENTRY_SEPARATOR = Pattern.compile("##|\\R");
	private static final Pattern DIGITS = Pattern.compile("\\d+");
	private static final Pattern COUNTRY_CODE = Pattern.compile("\\d{1,4}");
	// A new resolver is built for every SMS, so a bad rule would otherwise warn on every login.
	private static final Set<String> warned = ConcurrentHashMap.newKeySet();

	private final String defaultSenderId;
	private final String defaultRegion;
	private final Map<String, String> byRegion;
	private final List<Map.Entry<String, String>> byPrefix;

	SenderIdResolver(Map<String, String> config) {
		defaultSenderId = config.get("senderId");
		defaultRegion = regionForCountryCode(config.getOrDefault("countrycode", ""));

		Map<String, String> regions = new LinkedHashMap<>();
		List<Map.Entry<String, String>> prefixes = new ArrayList<>();
		parse(config.getOrDefault(OVERRIDES_CONFIG, ""), regions, prefixes);
		// Longest prefix first, so +1888 wins over +1.
		prefixes.sort(Comparator.comparingInt((Map.Entry<String, String> entry) -> entry.getKey().length()).reversed());

		byRegion = Collections.unmodifiableMap(regions);
		byPrefix = Collections.unmodifiableList(prefixes);
	}

	boolean hasOverrides() {
		return !byRegion.isEmpty() || !byPrefix.isEmpty();
	}

	String resolve(String phoneNumber) {
		if (!hasOverrides() || phoneNumber == null || phoneNumber.isBlank()) {
			return defaultSenderId;
		}

		String region = null;
		String mainRegion = null;
		String e164 = phoneNumber.startsWith("+") ? phoneNumber : null;
		try {
			PhoneNumberUtil util = PhoneNumberUtil.getInstance();
			Phonenumber.PhoneNumber parsed = util.parse(phoneNumber, defaultRegion);
			// getRegionCodeForNumber inspects the area code, so it tells US and CA apart on +1.
			region = util.getRegionCodeForNumber(parsed);
			// It returns null for a number that matches no region of a shared calling code, such as
			// a US number in an area code the bundled metadata does not know yet. Falling back to the
			// main region of the calling code keeps those on the sender the network requires.
			mainRegion = util.getRegionCodeForCountryCode(parsed.getCountryCode());
			e164 = util.format(parsed, PhoneNumberUtil.PhoneNumberFormat.E164);
		} catch (NumberParseException e) {
			logger.debugf("Sender ID override: cannot determine the country of %s, using the default sender ID", phoneNumber);
		}

		String sender = region != null ? byRegion.get(region) : null;
		if (sender == null && e164 != null) {
			for (Map.Entry<String, String> entry : byPrefix) {
				if (e164.startsWith(entry.getKey())) {
					sender = entry.getValue();
					break;
				}
			}
		}
		if (sender == null && mainRegion != null) {
			sender = byRegion.get(mainRegion);
		}

		if (sender == null) {
			return defaultSenderId;
		}
		logger.debugf("Sender ID override: using %s for %s", sender, region != null ? region : e164);
		return sender;
	}

	private void parse(String overrides, Map<String, String> regions, List<Map.Entry<String, String>> prefixes) {
		if (overrides == null || overrides.isBlank()) {
			return;
		}

		for (String entry : ENTRY_SEPARATOR.split(overrides)) {
			if (entry.isBlank()) {
				continue;
			}

			int separator = entry.indexOf('=');
			String sender = separator < 0 ? "" : entry.substring(separator + 1).trim();
			if (separator < 0 || sender.isEmpty()) {
				warnOnce("Ignoring sender ID override without a country or a sender: " + entry);
				continue;
			}

			for (String country : entry.substring(0, separator).split(",")) {
				addRule(country.trim(), sender, entry, regions, prefixes);
			}
		}
	}

	private void addRule(String country, String sender, String entry,
						 Map<String, String> regions, List<Map.Entry<String, String>> prefixes) {
		if (country.isEmpty()) {
			return;
		}

		String digits = country.startsWith("+") ? country.substring(1) : country;
		if (DIGITS.matcher(digits).matches()) {
			String prefix = "+" + digits;
			if (prefixes.stream().anyMatch(existing -> existing.getKey().equals(prefix))) {
				warnOnce("Ignoring duplicate sender ID override for " + prefix + ": " + entry);
				return;
			}
			prefixes.add(Map.entry(prefix, sender));
			return;
		}

		String region = country.toUpperCase(Locale.ROOT);
		if (!PhoneNumberUtil.getInstance().getSupportedRegions().contains(region)) {
			warnOnce("Ignoring sender ID override for unknown country " + country + ": " + entry);
			return;
		}
		if (regions.putIfAbsent(region, sender) != null) {
			warnOnce("Ignoring duplicate sender ID override for " + region + ": " + entry);
		}
	}

	private static String regionForCountryCode(String countrycode) {
		if (countrycode == null) {
			return null;
		}
		String digits = countrycode.startsWith("+") ? countrycode.substring(1) : countrycode;
		if (!COUNTRY_CODE.matcher(digits).matches()) {
			return null;
		}
		String region = PhoneNumberUtil.getInstance().getRegionCodeForCountryCode(Integer.parseInt(digits));
		// getRegionCodeForCountryCode returns "ZZ" for an unknown country code.
		return "ZZ".equals(region) ? null : region;
	}

	static void warnOnce(String message) {
		if (warned.add(message)) {
			logger.warn(message);
		}
	}
}
