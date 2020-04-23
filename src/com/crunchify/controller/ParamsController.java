package com.crunchify.controller;

import java.net.URLDecoder;
import java.net.URLEncoder;
import java.util.ArrayList;

import java.util.Date;
import java.util.List;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.ResponseBody;
import org.springframework.web.bind.annotation.RestController;
import org.springframework.web.servlet.ModelAndView;
 
import com.crunchify.controller.personbean;


import java.net.URL;
import java.text.DateFormat;
import java.text.SimpleDateFormat;
import java.util.ResourceBundle;

//ECQV
import java.io.FileNotFoundException;
import java.io.IOException;
import java.math.BigInteger;
import java.net.URISyntaxException;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.Key;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.Security;
import java.security.Signature;
import java.security.SignatureException;
import java.security.cert.CertificateEncodingException;

import javax.crypto.BadPaddingException;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;

import org.bouncycastle.jcajce.provider.asymmetric.ec.BCECPrivateKey;
import org.bouncycastle.jcajce.provider.asymmetric.ec.BCECPublicKey;
import org.bouncycastle.jce.ECNamedCurveTable;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.jce.spec.ECParameterSpec;
import org.bouncycastle.util.encoders.Base64;

import ca.trustpoint.m2m.KeyAlgorithmDefinition;
import ca.trustpoint.m2m.M2mSignatureAlgorithmOids;
import ca.trustpoint.m2m.SignatureAlgorithms;
import ca.trustpoint.m2m.M2mCertPath.SupportedEncodings;
import ca.trustpoint.m2m.ecqv.EcqvProvider;
import ca.trustpoint.m2m.ecqv.EcqvProvider2;
import ca.trustpoint.m2m.ecqv.KeyReconstructionData;



@Controller
public class ParamsController {	//注意：每次进来都会init不同的system/CA，需改动
	
	//INITIALIZE SYSTEM
	static UserKey userkey = new UserKey();
	KeyAlgorithmDefinition caKeyDefinition;
	SignatureAlgorithms caAlgorithm;
	EcqvProvider2 provider;
	KeyPairGenerator g;
	ECParameterSpec ecSpec;
	//INITIALIZE
	
	//INIT CA
	KeyPair caKeyPair;	//ca key pair
	//CA
	
	//USER DATA
	KeyReconstructionData keyReconData;
	KeyPair appendKey;
	BigInteger z;
	//USER
	
	@RequestMapping("/go")
	@ResponseBody
	public String gowhere(String num, String cer, String postT, String postZ) throws Exception {
		
		System.out.println("=======NOW CLINET IS COMING======");
		System.out.println("******cert = "+cer+"    ******");
		System.out.println("******t = "+postT+"    ******");
		System.out.println("******z = "+postZ+"    ******");
		//decode
		//String url = URLDecoder.decode(data, "UTF-8");
		//System.out.println("DATA(after decoding)="+url);
		
		//initial system and CA
		initial();
		initCA();
		
		switch(Integer.parseInt(num)) {
		case 1:
			System.out.println("ITS 1 and i will run REQECQV!");
			return reqECQV();
		case 2:
			System.out.println("ITS 2 and i will run VERECQV!");
			return verECQV(cer);
		case 3:
			System.out.println("ITS 3 and i will run proxyECQV!");
			return ProxyECQV();
		case 4:
			System.out.println("ITS 4 and i will run verProxyECQV!");
			return verProxyECQV(cer);
		case 5:
			System.out.println("ITS 5 and i will run updateECQV!");
			reqECQV();
			ProxyECQV();
			return UpdateECQV();
		case 6:
			System.out.println("ITS 6 and i will run verUpdateECQV!");
			System.out.println("******cert = "+cer+"    ******");
			System.out.println("******t = "+postT+"    ******");
			System.out.println("******z = "+postZ+"    ******");
			reqECQV();
			ProxyECQV();
			UpdateECQV();
			return verUpdateECQV(cer, postT, postZ);
		}
	    return "!!FAILED calling any function!!";
	}
	
	
	public void initial() throws InvalidAlgorithmParameterException, SignatureException, IOException, IllegalArgumentException,
	UnsupportedOperationException, NoSuchAlgorithmException, NoSuchProviderException, InvalidKeyException, NoSuchPaddingException, IllegalBlockSizeException, BadPaddingException, CertificateEncodingException, URISyntaxException {
		
			System.out.println("========Start Initial!!!!!!!========");
		   
		   Security.addProvider(new BouncyCastleProvider());
		   caKeyDefinition = new KeyAlgorithmDefinition();
		   caKeyDefinition.setAlgorithm(M2mSignatureAlgorithmOids.ECQV_SHA256_SECP256K1);
		   caAlgorithm = SignatureAlgorithms.getInstance(caKeyDefinition.getAlgorithm().getOid());
		   
		   provider = new EcqvProvider2(caAlgorithm, caKeyDefinition.getParameters());
		   g = KeyPairGenerator.getInstance("ECDSA", "BC");
		   ecSpec = ECNamedCurveTable.getParameterSpec("secp256k1");
		   g.initialize(ecSpec, new SecureRandom());
	}
	
	
	public void initCA() throws InvalidAlgorithmParameterException, SignatureException, IOException, IllegalArgumentException,
	UnsupportedOperationException, NoSuchAlgorithmException, NoSuchProviderException, InvalidKeyException, NoSuchPaddingException, IllegalBlockSizeException, BadPaddingException, CertificateEncodingException, URISyntaxException {
		
			System.out.println("========Start init CA!!!!!!!========");
			caKeyPair = g.generateKeyPair();	//ca key pair
	}
	
	
	public KeyReconstructionData callCA(byte[] tbsCertificate, PublicKey userRandomness) throws InvalidAlgorithmParameterException, SignatureException, IOException, IllegalArgumentException,
	UnsupportedOperationException, NoSuchAlgorithmException, NoSuchProviderException, InvalidKeyException, NoSuchPaddingException, IllegalBlockSizeException, BadPaddingException, CertificateEncodingException, URISyntaxException {
		
		return provider.genReconstructionData(tbsCertificate, userRandomness, caKeyPair.getPrivate());
	}
	
	
	public String reqECQV() throws InvalidAlgorithmParameterException, SignatureException, IOException, IllegalArgumentException,
	UnsupportedOperationException, NoSuchAlgorithmException, NoSuchProviderException, InvalidKeyException, NoSuchPaddingException, IllegalBlockSizeException, BadPaddingException, CertificateEncodingException, URISyntaxException {
	   

	   System.out.println("========Start req CA!!!!!!!!!!!!========");
	   
	   byte[] tbsCertificate = { 0x01, 0x02, 0x03 };	//hash of tbs cer maybe user info
	   KeyPair pair = g.generateKeyPair();	//randomness when request ECQV
	   
	   //call CA
	   keyReconData = callCA(tbsCertificate, pair.getPublic());
	   	   
	   //reconstruct
	   PublicKey reconstructedPublicKey = provider.reconstructPublicKey(provider.cert,
				keyReconData.getPublicKeyReconstructionData(), caKeyPair.getPublic());
	   System.out.println("**********========  RECON PUBKEY :   "+reconstructedPublicKey+"   ========********");

	   PrivateKey reconstructedPrivateKey = provider.reconstructPrivateKey(provider.cert,
				keyReconData.getPublicKeyReconstructionData(), keyReconData.getPrivateKeyReconstructionData(), pair.getPrivate());
	   System.out.println("**********========  RECON PPRIKEY :   "+reconstructedPrivateKey+"   ========********");
	   
	   userkey.setPub(reconstructedPublicKey);
	   userkey.setPri(reconstructedPrivateKey);
	   return byte2HexStr(reconstructedPublicKey.getEncoded());
	   
   }
	
	
	public String verECQV(String cer) throws InvalidAlgorithmParameterException, SignatureException, IOException, IllegalArgumentException,
	UnsupportedOperationException, NoSuchAlgorithmException, NoSuchProviderException, InvalidKeyException, NoSuchPaddingException, IllegalBlockSizeException, BadPaddingException, CertificateEncodingException, URISyntaxException {
		
		return "";
	}   
	
	
	public String ProxyECQV() throws InvalidAlgorithmParameterException, SignatureException, IOException, IllegalArgumentException,
	UnsupportedOperationException, NoSuchAlgorithmException, NoSuchProviderException, InvalidKeyException, NoSuchPaddingException, IllegalBlockSizeException, BadPaddingException, CertificateEncodingException, URISyntaxException {
		
		//generate proxy cer
		long tBegin, tEnd;	   
		tBegin = System.currentTimeMillis();//time calculating
		System.out.println("========Start generate proxy certificate!========");
		appendKey = g.generateKeyPair();
		System.out.println("append pri key : "+appendKey.getPrivate());
		System.out.println("append pub key : "+appendKey.getPublic());
		System.out.print("append pub key (under encoding string) : ");
		for(byte b:appendKey.getPublic().getEncoded()) {
			System.out.print(b);
		}
		System.out.println();
		PrivateKey newPri = provider.genNewKey1(appendKey.getPrivate(), appendKey.getPublic(), userkey.getPub(), userkey.getPri(), provider.cert, keyReconData.getPublicKeyReconstructionData());
		PublicKey newPub = (PublicKey) provider.getPubFromPri(newPri);		
		userkey.setNewPri(newPri);
		userkey.setNewPub(newPub);
		System.out.println("New PrivateKey : "+byte2HexStr(newPri.getEncoded()));
		System.out.println("New PublicKey  : "+byte2HexStr(newPub.getEncoded()));
		tEnd = System.currentTimeMillis();
		System.out.println("========End generate proxy certificate!=======");
		System.out.println("Stage of proxy certificate spend "+(tEnd-tBegin)+" millisecond");
		return byte2HexStr(newPub.getEncoded());
	} 
	
	
	public String UpdateECQV() throws InvalidAlgorithmParameterException, SignatureException, IOException, IllegalArgumentException,
	UnsupportedOperationException, NoSuchAlgorithmException, NoSuchProviderException, InvalidKeyException, NoSuchPaddingException, IllegalBlockSizeException, BadPaddingException, CertificateEncodingException, URISyntaxException {
	
		//Multiple key generation (method 2)
		System.out.println("\r\n=======Multiple Key Generate Method2 Begin=======");
		long tBegin, tEnd;
		tBegin = System.currentTimeMillis();
		System.out.println("append pri key : "+appendKey.getPrivate());
		System.out.println("append pub key : "+appendKey.getPublic());
		PrivateKey newPri2 = provider.genNewKey1(appendKey.getPrivate(), appendKey.getPublic(), userkey.getPub(), userkey.getPri(), provider.cert, keyReconData.getPublicKeyReconstructionData());
		PublicKey newPub2 = (PublicKey) provider.getPubFromPri(userkey.getNewPri());		
		userkey.setNewPri(newPri2);
		userkey.setNewPub(newPub2);
		System.out.println("New PrivateKey : "+byte2HexStr(newPri2.getEncoded()));
		System.out.println("New PublicKey  : "+byte2HexStr(newPub2.getEncoded()));
		z = provider.genNewKey2(appendKey.getPrivate(), appendKey.getPublic(), userkey.getPub(), userkey.getPri(), provider.cert);
		System.out.println("z : "+z);
		tEnd = System.currentTimeMillis();
		System.out.println("=======Multiple Key Generate Method2 End=======");
		System.out.println("Stage of Multiple Key Generation spend "+(tEnd-tBegin)+" millisecond");
				
		return byte2HexStr(newPub2.getEncoded());
	} 
	
	
	public String verProxyECQV(String cer) throws InvalidAlgorithmParameterException, SignatureException, IOException, IllegalArgumentException,
	UnsupportedOperationException, NoSuchAlgorithmException, NoSuchProviderException, InvalidKeyException, NoSuchPaddingException, IllegalBlockSizeException, BadPaddingException, CertificateEncodingException, URISyntaxException {
	
		System.out.println("\r\n=======Verify multiple Key Generation Method1 Begin=======");
		long tBegin,tEnd;
		tBegin = System.currentTimeMillis();
		//Verify Multiple key generation (method 1), B calculate new key
		PublicKey BnewQaKey = provider.verifyNewKey1(provider.cert, appendKey.getPublic(), caKeyPair.getPublic(), keyReconData.getPublicKeyReconstructionData());
		System.out.println("A New PublicKey  : "+ byte2HexStr(userkey.getNewPub().getEncoded()));
		System.out.println("B cal public key : "+byte2HexStr(BnewQaKey.getEncoded()));
		System.out.println("Verify : "+provider.verifyKeyPair(BnewQaKey, userkey.getNewPri()));
		tEnd = System.currentTimeMillis();
		System.out.println("=======Verify multiple Key Generation Method1 End=======");
		System.out.println("Stage of Multiple Key Generation spend "+(tEnd-tBegin)+" millisecond");
		
		return byte2HexStr(BnewQaKey.getEncoded());
	} 
	
	
	public String verUpdateECQV(String cer, String postT, String postZ) throws InvalidAlgorithmParameterException, SignatureException, IOException, IllegalArgumentException,
	UnsupportedOperationException, NoSuchAlgorithmException, NoSuchProviderException, InvalidKeyException, NoSuchPaddingException, IllegalBlockSizeException, BadPaddingException, CertificateEncodingException, URISyntaxException {
	
		//Verify Multiple key generation (method 2), B calculate new key and verified
		System.out.println("\r\n=======Verify multiple Key Generation Method2 Begin=======");
		long tBegin,tEnd;
		tBegin = System.currentTimeMillis();
		//Boolean result = provider.verifyNewKey2(z, provider.cert, appendKey.getPublic(), caKeyPair.getPublic(), keyReconData.getPublicKeyReconstructionData());
		BigInteger Z = new BigInteger(postZ);
		Boolean result = provider.verifyNewKey2(Z, cer, postT, caKeyPair.getPublic(), keyReconData.getPublicKeyReconstructionData());
		System.out.println(result);
		tEnd = System.currentTimeMillis();
		System.out.println("=======Verify multiple Key Generation Method2 End=======");
		System.out.println("Stage of Multiple Key Generation spend "+(tEnd-tBegin)+" millisecond");
		if(result==true)
			return "PASS VERIFICATION";
		return "FAIL VERIFICATION";
	}
	

	   /***** Data type exchange *****/
		private static String byte2HexStr(byte[] a) {
			StringBuilder sb = new StringBuilder(a.length * 2);
			for (byte b : a)
				sb.append(String.format("%02x", b & 0xff));
			return sb.toString().toUpperCase();
		}

		private static byte[] hexStr2Bytes(String s) {
			int len = s.length();
			byte[] data = new byte[len / 2];
			for (int i = 0; i < len; i += 2) {
				data[i / 2] = (byte) ((Character.digit(s.charAt(i), 16) << 4) + Character.digit(s.charAt(i + 1), 16));
			}
			return data;
		}
	
}
