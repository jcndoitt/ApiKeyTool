import javax.xml.bind.DatatypeConverter;

import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.keygen.BytesKeyGenerator;
import org.springframework.security.crypto.keygen.KeyGenerators;

public class ApiKeyGen {

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
    
    public static void main(String[] args) {
    	
    	Integer keyLength = KEY_LENGTH_DEFAULT;
    	Integer encodeStrength = ENCODE_STRENGTH_DEFAULT;
    	
    	for (int i = 0; i < args.length; i++) {
    		if ("-kl".equalsIgnoreCase(args[i]) && i <= (args.length-1)) {
    			keyLength = Integer.parseInt(args[i+1]);
    		}
    		else if ("-es".equalsIgnoreCase(args[i]) && i <= (args.length-1)) {
    			encodeStrength = Integer.parseInt(args[i+1]);
    		}
    		else if ("-h".equalsIgnoreCase(args[i]) || "-help".equalsIgnoreCase(args[i])) {
    	        System.err.println("Usage: ApiKeyGen [-kl <Key Length>] [-es <Encode Strength(4-31)>] [-help] ");
    	        return;
    		}
    	}
    	
    	ApiKeyGen apiKeyGen = new ApiKeyGen();
    	
		String key = apiKeyGen.generate(keyLength);
		String encodedKey = apiKeyGen.encode(key, encodeStrength);
		Boolean verified = apiKeyGen.verify(key, encodedKey, encodeStrength);
		
        System.err.println("Generate Key (Plaintext): " + key);
        System.err.println("Generate Key (Encoded): " + encodedKey);
        System.err.println("Is Verified: " + verified);
        System.err.println("Key Length: " + keyLength);
        System.err.println("Encode Strength (4 -31): " + encodeStrength);
        System.err.println("==================");
    }
    
}
