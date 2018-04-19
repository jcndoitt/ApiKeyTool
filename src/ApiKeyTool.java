import javax.xml.bind.DatatypeConverter;

import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.keygen.BytesKeyGenerator;
import org.springframework.security.crypto.keygen.KeyGenerators;

public class ApiKeyTool {

	static public final Integer KEY_LENGTH_DEFAULT = 256;
	static public final Integer ENCODE_STRENGTH_DEFAULT = 10;

    public String generate(final int keyLen) {
		BytesKeyGenerator generator = KeyGenerators.secureRandom(keyLen);
		byte[] encoded = generator.generateKey();
		return DatatypeConverter.printHexBinary(encoded).toLowerCase();
    }

    public String encode(final String str, final Integer encodeStrength) {
		BCryptPasswordEncoder encoder = new BCryptPasswordEncoder(encodeStrength);
		return encoder.encode(str);
    }

    public Boolean verify(final String plainText, final String encodedText, final int encodeStrength) {
		BCryptPasswordEncoder encoder = new BCryptPasswordEncoder(encodeStrength);
		return encoder.matches(plainText, encodedText);    
    }
    
    public static void showHelp() {
        System.err.println("Usage: ApiKeyTool [-g] [-e strToEncode] [-v plainText encodedText] [-kl <Key Length>] [-es <Encode Strength(4-31)>] [-help]");
        System.exit(0);
    }
    
    public static void main(String[] args) {
    	
    		Integer keyLength = KEY_LENGTH_DEFAULT;
    		Integer encodeStrength = ENCODE_STRENGTH_DEFAULT;
    		Boolean isGenerateKey = false;
    		String key = null;
    		String encodedKey = null;
    		Boolean verified = false;
    		
    		for (int i = 0; i < args.length; i++) {
    			if ("-g".equalsIgnoreCase(args[i])) {
    				isGenerateKey = true;
    			}
    			else if ("-e".equalsIgnoreCase(args[i]) && i <= (args.length-1)) {
    				key = args[i+1];
    			}
    			else if ("-v".equalsIgnoreCase(args[i]) && i <= (args.length-2)) {
    				key = args[i+1];
    				encodedKey = args[i+2];
    			}
    			else if ("-kl".equalsIgnoreCase(args[i]) && i <= (args.length-1)) {
    				keyLength = Integer.parseInt(args[i+1]);
    			}
    			else if ("-es".equalsIgnoreCase(args[i]) && i <= (args.length-1)) {
    				encodeStrength = Integer.parseInt(args[i+1]);
    			}
    			else if ("-h".equalsIgnoreCase(args[i]) || "-help".equalsIgnoreCase(args[i])) {
                showHelp();
    			}
    		}
	
		ApiKeyTool apiKeyTool = new ApiKeyTool();
				
		if (isGenerateKey) {
			key = apiKeyTool.generate(keyLength);
			encodedKey = apiKeyTool.encode(key, encodeStrength);
			verified = apiKeyTool.verify(key, encodedKey, encodeStrength);
			System.err.println("Generated Key (Plaintext): " + key);
			System.err.println("Generated Key (Encoded): " + encodedKey);
            System.err.println("Key Length: " + keyLength);
        } else if (key != null && encodedKey != null) {
            verified = apiKeyTool.verify(key, encodedKey, encodeStrength);
            System.err.println("Key (Plaintext): " + key);
            System.err.println("Key (Encoded): " + encodedKey);
		} else if (key != null) {
			encodedKey = apiKeyTool.encode(key, encodeStrength);
			verified = apiKeyTool.verify(key, encodedKey, encodeStrength);
			System.err.println("Key (Plaintext): " + key);
			System.err.println("Generated Key (Encoded): " + encodedKey);
        }
        else {
            showHelp();
        }
        
        System.err.println("Encode Strength (4 -31): " + encodeStrength);
        	System.err.println("Is Verified: " + verified);
		System.err.println("==================");
    }
    
}
