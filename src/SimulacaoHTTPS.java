import javax.crypto.*;
import java.math.BigInteger;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.spec.InvalidParameterSpecException;
import javax.crypto.spec.SecretKeySpec;
import javax.crypto.spec.IvParameterSpec;

public class SimulacaoHTTPS {

    public static void main(String[] args) throws NoSuchAlgorithmException, InvalidAlgorithmParameterException, NoSuchPaddingException, IllegalBlockSizeException, BadPaddingException, InvalidKeyException, InvalidParameterSpecException {

        String pString = "B10B8F96A080E01DDE92DE5EAE5D54EC52C99FBCFB06A3C69A6A9DCA52D23B616073E28675A23D189838EF1E2EE652C013ECB4AEA906112324975C3CD49B83BFACCBDD7D90C4BD7098488E9C219A73724EFFD6FAE5644738FAA31A4FF55BCCC0A151AF5F0DC8B4BD45BF37DF365C1A65E68CFDA76D4DA708DF1FB2BC2E4A4371";
        String gString = "A4D1CBD5C3FD34126765A442EFB99905F8104DD258AC507FD6406CFF14266D31266FEA1E5C41564B777E690F5504F213160217B4B01B886A5E91547F9E2749F4D7FBD7D3B9A92EE1909D0D2263F80A76A6A24C087A091F531DBF0A0169B6A28AD662A4D18E73AFA32D779D5918D08BC8858F4DCEF97C2A24855E6EEB22B3B2E5";

        /** Etapa 1: Geração de chave usando Diffie-Hellman: **/

        // "Alessandro e Guilherme." em decimal
        String aString = "651081011151159711010011411132101327111710510810410111410910146";
        //Alessandro e Guilherme em hexadecimal:
        // 16B3FB9EBD9410ED548B9538B8427A47ACF6CACEEE861BD01D82B221B0D1295E957869EA6F6028E9E289024864C854116532FE57A3EADC15B8DDCF77F814C7D9FE84B8226CB3E28F7EBAE7F323CACBDB8435EA7BF18FB981F99A29A10D97AA43FDD48C295834F6959B043F52F225E156C5CBC23B609DB5C8F5941B81DB104665

        //PASSO 1
        //Calcular: A = g^a mod p
        BigInteger p = new BigInteger(pString,16);
        BigInteger g = new BigInteger(gString,16);
        BigInteger a = new BigInteger(aString);
        BigInteger A = g.modPow(a, p);
        System.out.println("A: " + A);

        String Astring = converteHexadecimalParaString(A.toByteArray());
        System.out.println("Enviar para o professor o valor de A em hexadecimal: \n" + Astring);

        //PASSO 2
        String Bstring = "31B69140823C5FE6659505F38B8A2A0E35E799411B22A24A1E1510BD7991E05760CD556A9686A5F879DFF9BCBD39E8CE4D114741C48030D912E2D3126150F0918A436D68C0A6C8F29A9AC41AF5507D3934133545723865B0531FC1A7CF3693E2EABB2C482FDE878E6E6947B2C9FC3A31E71BEFDC8CA474C203B19F9A739749FB";
        BigInteger B = new BigInteger(Bstring, 16);
        //Calcular V = B^a mod p
        BigInteger V = B.modPow(a,p);

        //PASSO 3
        //Calcular o S - SHA256(V)
        byte[] S = sha256(V.toByteArray());

        //Calcular o K
        String K = criarSenha(S);

        /** Etapa 2**/

        String MSG_CIFRADA = "D2D899A63687B5C3B199C60E531A39F522AF5287F5C2D6C2F375B80D790021A10D56156EB9C9B8B0096130E4B4D4A7E530B4CDC587CC66ED9376514AFBE3CE4E2CD12D27CA0EF3151E23E8AA0AF6C9C59264EB86B57991467473F43A2894F563D45EF9B6DF58DA1297E0E6E7A17AE04AC63694CAEE2B850EA95A646AF1E68EFB90ED55B16D7C34A6726B47FD8793EA82";
        String IV = MSG_CIFRADA.substring(0,32);
        String MSG = MSG_CIFRADA.substring(32);
        String MSG_DEOGRAFADA = decryptMessage(MSG, hexStringToByteArray(K), hexStringToByteArray(IV));
        System.out.println("______________________________________________________________________\n");
        System.out.println("Mensagem decodificada: " + MSG_DEOGRAFADA);
        String MSG_DEOGRAFADA_INVERTIDA = new StringBuilder(MSG_DEOGRAFADA).reverse().toString();
        System.out.println("Mensagem invertida: " + MSG_DEOGRAFADA_INVERTIDA);
        String MSG_ENCRIPTOGRAFADA = encryptMessage(MSG_DEOGRAFADA_INVERTIDA, hexStringToByteArray(K));
        System.out.println("Mensagem cifrada: " + MSG_ENCRIPTOGRAFADA);
    }

    public static String converteHexadecimalParaString(byte[] byteArray) {
        StringBuilder hexStringBuilder = new StringBuilder();
        for (int i = 0; i < byteArray.length; i++) {
            hexStringBuilder.append(converteByteParaHexadecimal(byteArray[i]));
        }
        return hexStringBuilder.toString().toUpperCase();
    }

    public static String converteByteParaHexadecimal(byte num) {
        char[] hexDigits = new char[2];
        hexDigits[0] = Character.forDigit((num >> 4) & 0xF, 16);
        hexDigits[1] = Character.forDigit((num & 0xF), 16);
        return new String(hexDigits);
    }

    public static byte[] sha256(byte[] input) throws NoSuchAlgorithmException {
        return hashString(input);
    }

    private static byte[] hashString(byte[] input) throws NoSuchAlgorithmException {
        return MessageDigest.getInstance("SHA-256").digest(input);
    }

    private static String criarSenha(byte[] S){
        byte[] array = buscarElementosArray(S, 16);
        return converteHexadecimalParaString(array);
    }

    private static byte[] buscarElementosArray(byte[] arrayEntrada, int n) {
        byte[] arraySaida = new byte[n];
        for(int i=0; i<n; i++){
            arraySaida[i] = arrayEntrada[i];
        }
        return arraySaida;
    }

    private static String decryptMessage(String msg, byte[] K, byte[] IV) throws NoSuchPaddingException, NoSuchAlgorithmException, IllegalBlockSizeException, BadPaddingException, InvalidAlgorithmParameterException, InvalidKeyException {
        var cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
        SecretKey key = new SecretKeySpec(K, "AES");
        cipher.init(Cipher.DECRYPT_MODE, key, new IvParameterSpec(IV));
        var plainText = cipher.doFinal(hexStringToByteArray(msg));
        return new String(plainText);
    }

    public static byte[] hexStringToByteArray(String s) {
        int len = s.length();
        byte[] data = new byte[len / 2];
        for (int i = 0; i < len; i += 2) {
            data[i / 2] = (byte) ((Character.digit(s.charAt(i), 16) << 4)
                    + Character.digit(s.charAt(i+1), 16));
        }
        return data;
    }

    private static String encryptMessage(String msg, byte[] K) throws IllegalBlockSizeException, BadPaddingException, InvalidAlgorithmParameterException, InvalidKeyException, NoSuchPaddingException, NoSuchAlgorithmException, InvalidParameterSpecException {
        var cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
        SecretKey key = new SecretKeySpec(K, "AES");
        byte[] IV = cipher.getParameters().getParameterSpec(IvParameterSpec.class).getIV();
        cipher.init(Cipher.ENCRYPT_MODE, key, new IvParameterSpec(IV));
        var cipherText = cipher.doFinal(msg.getBytes());
        return converteHexadecimalParaString(concatenarArrays(IV, cipherText));
    }

    public static byte[] concatenarArrays(byte[] IV, byte[] cipherText){
        byte[] mensagem = new byte[IV.length + cipherText.length];
        System.arraycopy(IV, 0, mensagem, 0, IV.length);
        System.arraycopy(cipherText, 0, mensagem, IV.length, cipherText.length);
        return mensagem;
    }


    /** REFERÊNCIAS:
     *
     * hexStringToByteArray
     * https://stackoverflow.com/questions/140131/convert-a-string-representation-of-a-hex-dump-to-a-byte-array-using-java
     *
     * juntarDoisArrays
     * https://pt.stackoverflow.com/questions/65117/como-concatenar-dois-arrays-de-byte-em-java
     */
}


