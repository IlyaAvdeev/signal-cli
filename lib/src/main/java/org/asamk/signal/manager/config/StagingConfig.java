package org.asamk.signal.manager.config;

import org.bouncycastle.util.encoders.Hex;
import org.signal.libsignal.protocol.InvalidKeyException;
import org.signal.libsignal.protocol.ecc.Curve;
import org.signal.libsignal.protocol.ecc.ECPublicKey;
import org.whispersystems.signalservice.api.push.TrustStore;
import org.whispersystems.signalservice.internal.configuration.SignalCdnUrl;
import org.whispersystems.signalservice.internal.configuration.SignalCdsiUrl;
import org.whispersystems.signalservice.internal.configuration.SignalContactDiscoveryUrl;
import org.whispersystems.signalservice.internal.configuration.SignalKeyBackupServiceUrl;
import org.whispersystems.signalservice.internal.configuration.SignalProxy;
import org.whispersystems.signalservice.internal.configuration.SignalServiceConfiguration;
import org.whispersystems.signalservice.internal.configuration.SignalServiceUrl;
import org.whispersystems.signalservice.internal.configuration.SignalStorageUrl;

import java.util.Base64;
import java.util.Collection;
import java.util.List;
import java.util.Map;
import java.util.Optional;

import okhttp3.Dns;
import okhttp3.Interceptor;

class StagingConfig {

    private final static byte[] UNIDENTIFIED_SENDER_TRUST_ROOT = Base64.getDecoder()
            .decode("Bdm8mxmX6PwvFloZpSVNwEjPTxk7mGb3QBZefzZnFr82");
    private final static String CDS_MRENCLAVE = "5282dd8af2448dbf3881d1631d92c63b8fc9a5f48f6e234e16e3a561619aaca9";
    private final static String CDSI_MRENCLAVE = "5282dd8af2448dbf3881d1631d92c63b8fc9a5f48f6e234e16e3a561619aaca9";

    private final static String KEY_BACKUP_ENCLAVE_NAME = "39963b736823d5780be96ab174869a9499d56d66497aa8f9b2244f777ebc366b";
    private final static byte[] KEY_BACKUP_SERVICE_ID = Hex.decode(
            "9dbc6855c198e04f21b5cc35df839fdcd51b53658454dfa3f817afefaffc95ef");
    private final static String KEY_BACKUP_MRENCLAVE = "45627094b2ea4a66f4cf0b182858a8dcf4b8479122c3820fe7fd0551a6d4cf5c";
    private final static String FALLBACK_KEY_BACKUP_ENCLAVE_NAME = "dd6f66d397d9e8cf6ec6db238e59a7be078dd50e9715427b9c89b409ffe53f99";
    private final static byte[] FALLBACK_KEY_BACKUP_SERVICE_ID = Hex.decode(
            "4200003414528c151e2dccafbc87aa6d3d66a5eb8f8c05979a6e97cb33cd493a");
    private final static String FALLBACK_KEY_BACKUP_MRENCLAVE = "ee19f1965b1eefa3dc4204eb70c04f397755f771b8c1909d080c04dad2a6a9ba";

    private final static String URL = System.getProperty("stagingServerURL","https://staging.signal-v2.devinoi.com");
    private final static String CDN_URL = System.getProperty("stagingCdnURL","https://staging.cdn.devinoi.com");
    private final static String CDN2_URL = System.getProperty("stagingCdn2URL","https://staging.cdn2.devinoi.com");
    private final static String SIGNAL_CONTACT_DISCOVERY_URL = System.getProperty("stagingContactDiscoveryURL",
            "https://staging.cds.devinoi.com");
    private final static String SIGNAL_KEY_BACKUP_URL = System.getProperty("stagingKeyBackupURL",
            "https://staging.svr.devinoi.com");
    private final static String STORAGE_URL = System.getProperty("stagingStorageURL","https://staging.storage.devinoi.com");
    private final static String SIGNAL_CDSI_URL = System.getProperty("stagingCdsiURL","https://staging.cds.devinoi.com");

    private final static TrustStore TRUST_STORE = new WhisperTrustStore();

    private final static Optional<Dns> dns = Optional.empty();
    private final static Optional<SignalProxy> proxy = Optional.empty();

    private final static byte[] zkGroupServerPublicParams = Base64.getDecoder()
            .decode("AH7eCL2GYrFC17xX3eEQLCst0piBYyr690Xjql2KfFB+qhGMzPLZxJPPxPiLvnqlqDbJ6tRW3nIlkilSpsQV7hwQ6S4LZXoPXhJl3O6iQW1BKIk/K+1DfSpB8YF8Xo1dQcBzY2JoPcvIxxSu2Ey97sCt0gOlrWjmtfqFZPX8GStO6Gcxsvtr2p3xYZEwn//gGlrSD1Q7Rr8i067QIP+/x368yKgXdLhykf6zT54+jjrpDW5ZNSD0znJmGLTXShrfP2ZyVqZcbxpc4QgjWM0pHM7NCwe/Xnax/ksJ3NQ5wNYM0o7gfhJJw/IjKEo3vNec4obmnQ9ZaBBpwQ05ud+LaBO61kfJKRG8m4Ko/edKgezqYyFULMK+BqXbwj5kQC6pZ5rWPzr3Gam7b88/u6U9n/V9WpF1y5+YyzTYwQ/+xfkOIHFtEBUhUuTdAvTAAVE+nX7nwRswbqE72KQ/wYjGZCdO4uL0rMOvGc7jdW0GHKUgBqi7zAQdPpBaq2ybTCedVJjR9S+lNmYzSVHsdoWJKKNiIfx9IpOWbzgdZ5k4jzMG");

    static SignalServiceConfiguration createDefaultServiceConfiguration(
            final List<Interceptor> interceptors
    ) {
        return new SignalServiceConfiguration(new SignalServiceUrl[]{new SignalServiceUrl(URL, TRUST_STORE)},
                Map.of(0,
                        new SignalCdnUrl[]{new SignalCdnUrl(CDN_URL, TRUST_STORE)},
                        2,
                        new SignalCdnUrl[]{new SignalCdnUrl(CDN2_URL, TRUST_STORE)}),
                new SignalContactDiscoveryUrl[]{
                        new SignalContactDiscoveryUrl(SIGNAL_CONTACT_DISCOVERY_URL, TRUST_STORE)
                },
                new SignalKeyBackupServiceUrl[]{new SignalKeyBackupServiceUrl(SIGNAL_KEY_BACKUP_URL, TRUST_STORE)},
                new SignalStorageUrl[]{new SignalStorageUrl(STORAGE_URL, TRUST_STORE)},
                new SignalCdsiUrl[]{new SignalCdsiUrl(SIGNAL_CDSI_URL, TRUST_STORE)},
                interceptors,
                dns,
                proxy,
                zkGroupServerPublicParams);
    }

    static ECPublicKey getUnidentifiedSenderTrustRoot() {
        try {
            return Curve.decodePoint(UNIDENTIFIED_SENDER_TRUST_ROOT, 0);
        } catch (InvalidKeyException e) {
            throw new AssertionError(e);
        }
    }

    static KeyBackupConfig createKeyBackupConfig() {
        return new KeyBackupConfig(KEY_BACKUP_ENCLAVE_NAME, KEY_BACKUP_SERVICE_ID, KEY_BACKUP_MRENCLAVE);
    }

    static Collection<KeyBackupConfig> createFallbackKeyBackupConfigs() {
        return List.of(new KeyBackupConfig(FALLBACK_KEY_BACKUP_ENCLAVE_NAME,
                FALLBACK_KEY_BACKUP_SERVICE_ID,
                FALLBACK_KEY_BACKUP_MRENCLAVE));
    }

    static String getCdsMrenclave() {
        return CDS_MRENCLAVE;
    }

    static String getCdsiMrenclave() {
        return CDSI_MRENCLAVE;
    }

    private StagingConfig() {
    }
}
