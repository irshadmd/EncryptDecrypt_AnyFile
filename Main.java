import javax.crypto.Cipher;
import javax.crypto.CipherInputStream;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.File;
import java.io.FileInputStream;
import java.net.MalformedURLException;
import java.net.URI;
import java.net.URISyntaxException;
import java.net.URL;
import java.nio.file.Paths;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;

public class Main{
    public static void main(String[] args) throws IOException, InvalidKeyException, URISyntaxException, NoSuchPaddingException, NoSuchAlgorithmException {
        Main m=new Main();
        String type=args[0];
        String url=args[1];
        String apiKey=args[2];

        if(type.equals("-en")){
            EncryptionRequest er=new EncryptionRequest();
            er.setUrl(url);
            er.setApiKey(apiKey);
            EncryptionResponse eres= m.setEncryption(er);
			System.out.println(eres.getEncURL());
			System.out.println(eres.getStatus());
			System.out.println(eres.getMassage());
        }else if(type.equals("-de")){
			DecryptionRequest dr=new DecryptionRequest();
			dr.setUrl(url);
			dr.setApiKey(apiKey);
			DecryptionResponse dres=m.setDecryption(dr);
            System.out.println(dres.getDecURL());
            System.out.println(dres.getStatus());
            System.out.println(dres.getMassage());
        }else{
            System.out.println("Invalid Command");
		}
    }

    public EncryptionResponse setEncryption(EncryptionRequest encryptionRequest) throws MalformedURLException, IOException, InvalidKeyException, URISyntaxException {
		EncryptionResponse encryptionResponse=new EncryptionResponse();
		if(encryptionRequest.getApiKey().equals(ApplicationConstants.apikey)) {
			String url = encryptionRequest.getUrl();
//			InputStream inputStream = new URL(url).openStream();
			InputStream inputStream = new FileInputStream(new File(url));
// 			String fileName = Paths.get(new URI(url).getPath()).getFileName().toString();
            String[] parts=url.split("/");
			String fileName = parts[parts.length-1];

            byte[] key = CipherCommon.PBKDF2(ApplicationConstants.secetKey.toCharArray(),CipherCommon.salt);
            SecretKeySpec mSecretKeySpec = new SecretKeySpec(key, CipherCommon.AES_ALGORITHM);
            IvParameterSpec mIvParameterSpec = new IvParameterSpec(CipherCommon.iv);
            // String webrootDirectory=ApplicationConstants.directoryDriveName+ApplicationConstants.webrootDirectory+fileName+".enc";
            String webrootDirectory=url+".enc";
            FileOutputStream fos = new FileOutputStream(webrootDirectory);
            CipherInputStream cis;
            Cipher cipher = null;
            try {
                cipher = Cipher.getInstance(CipherCommon.AES_TRANSFORMATION);
                cipher.init(Cipher.ENCRYPT_MODE, mSecretKeySpec, mIvParameterSpec);
                cis = new CipherInputStream(inputStream, cipher);
                int b;
                byte[] d = new byte[8];
                while ((b = cis.read(d)) != -1) {
                    fos.write(d, 0, b);
                }
            } catch (Exception e) {
                e.printStackTrace();
            }finally {
                fos.flush();
                fos.close();
            }
			encryptionResponse.setEncURL(url+".enc");
			encryptionResponse.setMassage("Encrpytion have been done");
			encryptionResponse.setStatus("success");
			return encryptionResponse;
		}else {
			encryptionResponse.setEncURL("");
			encryptionResponse.setMassage("Invalid api key");
			encryptionResponse.setStatus("Failed");
			return encryptionResponse;
        }	  
	}

	public DecryptionResponse setDecryption(DecryptionRequest decryptionRequest) throws MalformedURLException, IOException, InvalidKeyException, NoSuchAlgorithmException, NoSuchPaddingException, URISyntaxException {
		DecryptionResponse decryptionResponse=new DecryptionResponse();
		if(decryptionRequest.getApiKey().equals(ApplicationConstants.apikey)) {
			String url = decryptionRequest.getUrl();
//			InputStream inputStream = new URL(url).openStream();
			InputStream inputStream = new FileInputStream(new File(url));
// 			String fileName = Paths.get(new URI(url).getPath()).getFileName().toString();
            String[] parts=url.split("/");
			String fileName = parts[parts.length-1];
            fileName=fileName.substring(0,fileName.length()-4);

			byte[] key = CipherCommon.PBKDF2(ApplicationConstants.secetKey.toCharArray(),CipherCommon.salt);
			SecretKeySpec mSecretKeySpec = new SecretKeySpec(key, CipherCommon.AES_ALGORITHM);
			IvParameterSpec mIvParameterSpec = new IvParameterSpec(CipherCommon.iv);
			// String webrootDirectory=ApplicationConstants.directoryDriveName+ApplicationConstants.webrootDirectory+fileName;
			String webrootDirectory=url.substring(0,url.length()-4);
			FileOutputStream fos = new FileOutputStream(webrootDirectory);
			CipherInputStream cis;
			Cipher cipher = null;
			try {
				cipher = Cipher.getInstance(CipherCommon.AES_TRANSFORMATION);
				cipher.init(Cipher.DECRYPT_MODE, mSecretKeySpec, mIvParameterSpec);
				cis = new CipherInputStream(inputStream, cipher);
				int b;
				byte[] d = new byte[8];
				while ((b = cis.read(d)) != -1) {
					fos.write(d, 0, b);
				}

			} catch (Exception e) {
				e.printStackTrace();
			}finally {
				fos.flush();
				fos.close();
			}
			decryptionResponse.setDecURL(url.substring(0,url.length()-4));
			decryptionResponse.setMassage("Decrpytion have been done");
			decryptionResponse.setStatus("success");
			return decryptionResponse;
		}else {
			decryptionResponse.setDecURL("");
			decryptionResponse.setMassage("Invalid api key");
			decryptionResponse.setStatus("Failed");
			return decryptionResponse;
		}
	}
}