import java.math.BigInteger;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;

public class SimulacaoHTTPS {

    public static void main(String[] args) throws NoSuchAlgorithmException {

        String pString = "B10B8F96A080E01DDE92DE5EAE5D54EC52C99FBCFB06A3C69A6A9DCA52D23B616073E28675A23D189838EF1E2EE652C013ECB4AEA906112324975C3CD49B83BFACCBDD7D90C4BD7098488E9C219A73724EFFD6FAE5644738FAA31A4FF55BCCC0A151AF5F0DC8B4BD45BF37DF365C1A65E68CFDA76D4DA708DF1FB2BC2E4A4371";
        String gString = "A4D1CBD5C3FD34126765A442EFB99905F8104DD258AC507FD6406CFF14266D31266FEA1E5C41564B777E690F5504F213160217B4B01B886A5E91547F9E2749F4D7FBD7D3B9A92EE1909D0D2263F80A76A6A24C087A091F531DBF0A0169B6A28AD662A4D18E73AFA32D779D5918D08BC8858F4DCEF97C2A24855E6EEB22B3B2E5";

        /** Etapa 1: Geração de chave usando Diffie-Hellman: **/

        String aString = "65766983836578688279327769686973827983"; // "ALESSANDRO MEDEIROS" em decimal

        //PASSO 1
        //Calcular: A = g^a mod p
        BigInteger p = new BigInteger(pString, 16);
        BigInteger g = new BigInteger(gString, 16);
        BigInteger a = new BigInteger(aString, 16);
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
        System.out.println("\n"+converteHexadecimalParaString(S));

        String primeiros128bitsDeS = converteHexadecimalParaString(S).substring(0, 128);


        /** Etapa 2**/

        String MSG_CIFRADA = "22243A7261D19DD22308EB3E444A83F376EB9B30949A6CAC4776EB9B30949A6CAC4770D6B0C2ED300D1F379C427D94A8986B9796FE2CFF44D6EE8E2A42956D894B2A0953B663F42CAC385E2A9CD5E4E87163A99C0B6153174E3B60907DFA75479BF746960D20DB98CECAF6BBAD74C68F1078B808C7D8E3A2BF46C1303B34BD619A0310A70D7039EDF7";
        String IV = MSG_CIFRADA.substring(0,32);
        String MSG = MSG_CIFRADA.substring(MSG_CIFRADA.length() - 32);
        //String MSG_DESCRIPTOGRAFADA = descriptografarMensagem(MSG_CIFRADA, primeiros128bitsDeS, converteHexadecimalParaString(IV));

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
}
