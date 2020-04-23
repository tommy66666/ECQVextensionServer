/**
 *  Copyright 2016 TrustPoint Innovation Technologies, Ltd.
 *
 *  Licensed under the Apache License, Version 2.0 (the "License");
 *  you may not use this file except in compliance with the License.
 *  You may obtain a copy of the License at
 *
 *  http://www.apache.org/licenses/LICENSE-2.0
 *
 *  Unless required by applicable law or agreed to in writing, software
 *  distributed under the License is distributed on an "AS IS" BASIS,
 *  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 *  See the License for the specific language governing permissions and
 *  limitations under the License.
 */

package ca.trustpoint.m2m.ecqv;

import java.io.IOException;
import java.math.BigInteger;
import java.net.URI;
import java.net.URISyntaxException;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.cert.CertificateEncodingException;
import java.util.Calendar;
import java.util.Date;
import java.util.GregorianCalendar;

import org.bouncycastle.asn1.ASN1Encodable;
import org.bouncycastle.asn1.ASN1EncodableVector;
import org.bouncycastle.asn1.ASN1Integer;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.ASN1Primitive;
import org.bouncycastle.asn1.BERSequence;
import org.bouncycastle.asn1.BERTaggedObject;
import org.bouncycastle.asn1.DERSequence;
import org.bouncycastle.asn1.DERSet;
import org.bouncycastle.asn1.DERTaggedObject;
import org.bouncycastle.asn1.pkcs.PKCSObjectIdentifiers;
import org.bouncycastle.asn1.pkcs.PrivateKeyInfo;
import org.bouncycastle.asn1.x509.AlgorithmIdentifier;
import org.bouncycastle.asn1.x509.SubjectPublicKeyInfo;
import org.bouncycastle.asn1.x9.X962Parameters;
import org.bouncycastle.asn1.x9.X9ObjectIdentifiers;
import org.bouncycastle.jcajce.provider.asymmetric.ec.BCECPrivateKey;
import org.bouncycastle.jcajce.provider.asymmetric.ec.BCECPublicKey;
import org.bouncycastle.jce.ECNamedCurveTable;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.jce.spec.ECParameterSpec;
import org.bouncycastle.math.ec.ECPoint;
import org.bouncycastle.util.encoders.Base64;
import org.bouncycastle.util.encoders.Hex;

import ca.trustpoint.m2m.AuthorityKeyIdentifier;
import ca.trustpoint.m2m.EntityName;
import ca.trustpoint.m2m.EntityNameAttribute;
import ca.trustpoint.m2m.EntityNameAttributeId;
import ca.trustpoint.m2m.GeneralName;
import ca.trustpoint.m2m.GeneralNameAttributeId;
import ca.trustpoint.m2m.KeyAlgorithmDefinition;
import ca.trustpoint.m2m.KeyUsage;
import ca.trustpoint.m2m.M2mCertificate;
import ca.trustpoint.m2m.M2mSignatureAlgorithmOids;
import ca.trustpoint.m2m.SignatureAlgorithms;
import ca.trustpoint.m2m.M2mCertPath.SupportedEncodings;
import ca.trustpoint.m2m.util.KeyConversionUtils;

/**
 * Provides functionality to support Elliptic Curve Qu-Vanstone (ECQV) key
 * reconstruction.
 */
public class EcqvProvider2 {
	/** Random number generator to be used for key generation. */
	private static final SecureRandom random = new SecureRandom();

	private MessageDigest digest, m1newdigest, m2newdigest, cdigest, bdigest, bm1newdigest, bm2newdigest,bcdigest;
	private ECParameterSpec curveParameters;
	private AlgorithmIdentifier algorithmId;
	
	private static byte[] fullCertData;
	private static byte[] rootcaData; 
	private static byte[] issuerData; 
	private static byte[] signerData; 
	private static byte[] pkiPathInputData;
	private static byte[] pkcs7InputData;
	private static byte[][] expectedCertPathData;
	private static final SupportedEncodings[] expectedEncodings = { SupportedEncodings.PKIPATH,
			SupportedEncodings.PKCS7 };
	public static M2mCertificate cert;
	static {
		// A certificate chain
		rootcaData = Base64.decode("dIIBTqCBvYEBAoIFK4E6AQ2kCoYIYmx1ZWxpbmWFBFeXxRGGBAHhM4CnCoYIYmx1ZWxpbmWIBSuBOgEN"
				+ "ioGFBAB47wWdYFq4W2olpu8xoac6Yy08sE3GBqjKC1gjlmFoz69hMdjZtT9r32tilG7EtB1hj6P/f4u/"
				+ "rL/U9k/jwz2p0gCkeuUo3FC284dtf1ujwILZkndR4ajE+TTZCUKzXFff4xGyZj6NAYetTt4xv5zSrYMX"
				+ "EHNgUi/baXWrLNZtwCmYH4GBizCBiAJCAU8VyvjvOGJrLHz6hblUTgKGaCkMrbRfYuIVPqr1qdUa9b8N"
				+ "AvLAV9OFa1y/s1KcJbhIFAWSQDn6YS1CKumhqFWRAkIBho09/l/Cvt0vdGiwsX7ScI52zQ03xE9NC7iG"
				+ "k3UgRvz8VtmBizJTO4mSkjwsgUmUAKxE+77NYyTYrh3UHsc6Cyo=");
		issuerData = Base64.decode("dIIBB6B4gQFlggUrgToBDaQKhghibHVlbGluZYUEV5kOX4YEA8JnAKcKhghNeUlzc3VlcogFK4E6AQmK"
				+ "QQRhWR53nuSCVBz2PvKgcJ09BM6+H2IdR2Tv7MT/N0hkMF43QtqyaQ6Im4SQan0uq0RLngO1Rjk7/Pmy"
				+ "s7h2WMb6gYGKMIGHAkIBao9QiZGTvYX/NpZRKfhvZCkLZPrUDnVco2fTGzSE8qVVLdqwWxJGMEz8QWTi"
				+ "mVDVbeoEu02aPUieBxBtHT80Zp0CQWMe0IzX7q/mEUGJU8ZPGmCXtF0au1+5OQo86u2rPEf/PnoadU4e"
				+ "DVOywv7pDrFOvaC08VJgw3X/wYaKdWm1Bf8I");
		signerData = Base64.decode("dIG8oHGBAWiCBSuBOgEJpAqGCE15SXNzdWVyhQRXomvMhgQDwmcApwqGCE15U2lnbmVyikEEY8d5z/RO"
				+ "s8l9fN+as62abtDctvPxoxVd9nQQmjqtCnV/yvLwHlPN7SVwetw4wicekLtVTbTtR7ZbJbtHjp47+IFH"
				+ "MEUCIQDL2Wnu62N6A9YLMnG9cyDno92hse8BTmQfbDK/iX7qxgIgMP9//TpZybFvLzNXFrR0AqPP8+5m"
				+ "d2eokBfSGCA81m4=");
	}

	/**
	 * Create a new instance.
	 *
	 * @param algorithm
	 *            Required. Signature algorithm OID.
	 * @param parameters
	 *            Optional. Algorithm parameters. (not currently used)
	 */
	public EcqvProvider2(SignatureAlgorithms algorithm, byte[] parameters) throws IllegalArgumentException,
			UnsupportedOperationException, NoSuchAlgorithmException, NoSuchProviderException {
		if (algorithm == null) {
			throw new IllegalArgumentException("Missing algorithm OID");
		} else if (!algorithm.isEcqv()) {
			throw new UnsupportedOperationException("This provider can only be used with ECQV-based signature types");
		}

		X962Parameters x9params = new X962Parameters(new ASN1ObjectIdentifier(algorithm.getSecOid()));

		digest = MessageDigest.getInstance(algorithm.getDigestAlgorithm().getDigestName(),
				BouncyCastleProvider.PROVIDER_NAME);
		m1newdigest = MessageDigest.getInstance(algorithm.getDigestAlgorithm().getDigestName(),
				BouncyCastleProvider.PROVIDER_NAME);
		m2newdigest = MessageDigest.getInstance(algorithm.getDigestAlgorithm().getDigestName(),
				BouncyCastleProvider.PROVIDER_NAME);
		cdigest = MessageDigest.getInstance(algorithm.getDigestAlgorithm().getDigestName(),
				BouncyCastleProvider.PROVIDER_NAME);
		bdigest = MessageDigest.getInstance(algorithm.getDigestAlgorithm().getDigestName(),
				BouncyCastleProvider.PROVIDER_NAME);
		bm1newdigest = MessageDigest.getInstance(algorithm.getDigestAlgorithm().getDigestName(),
				BouncyCastleProvider.PROVIDER_NAME);
		bm2newdigest = MessageDigest.getInstance(algorithm.getDigestAlgorithm().getDigestName(),
				BouncyCastleProvider.PROVIDER_NAME);
		bcdigest = MessageDigest.getInstance(algorithm.getDigestAlgorithm().getDigestName(),
				BouncyCastleProvider.PROVIDER_NAME);
		curveParameters = ECNamedCurveTable.getParameterSpec(algorithm.getCryptoAlgorithm().getAlgorithmName());
		algorithmId = new AlgorithmIdentifier(X9ObjectIdentifiers.id_ecPublicKey, x9params.toASN1Primitive());
	}

	/**
	 * Create a new instance.
	 *
	 * @param algorithmOid
	 *            Required. Signature algorithm OID.
	 * @param parameters
	 *            Optional. Algorithm parameters. (not currently used)
	 */
	public EcqvProvider2(String algorithmOid, byte[] parameters) throws IllegalArgumentException,
			UnsupportedOperationException, NoSuchAlgorithmException, NoSuchProviderException {
		this(SignatureAlgorithms.getInstance(algorithmOid), parameters);
	}

	/**
	 * Generate reconstruction data for an implicit certificate In the
	 * terminology of sec4, ephemeralPublicKey is referenced as Ru
	 *
	 * @param identifyingInfo
	 *            the identity portion of the implicit certificate
	 * @param ephemeralPublicKey
	 *            the requesters ephemeral public key
	 * @param issuerPrivateKey
	 *            the issuers private key
	 *
	 * @return reconstruction data associated with the implicit certificate
	 *
	 * @throws NoSuchAlgorithmException
	 *             From Bouncy Castle
	 * @throws InvalidAlgorithmParameterException
	 *             From Bouncy Castle
	 * @throws NoSuchProviderException
	 *             From Bouncy Castle
	 * @throws IOException
	 * @throws InvalidKeyException 
	 * @throws URISyntaxException 
	 * @throws CertificateEncodingException 
	 */
	public KeyReconstructionData genReconstructionData(byte[] identifyingInfo, PublicKey ephemeralPublicKey,
			PrivateKey issuerPrivateKey)
			throws NoSuchAlgorithmException, InvalidAlgorithmParameterException, NoSuchProviderException, IOException, InvalidKeyException, URISyntaxException, CertificateEncodingException {

		// Reconstruction point, in point and byte format
		ECPoint p = null;
		byte[] reconstructionPoint;

		// CA's ephemeral key pair (k, kG)
		BCECPublicKey caEphemeralPublicKey = null;
		BCECPrivateKey caEphemeralPrivateKey =null;

		BigInteger n = curveParameters.getN(); // get the order of the curve
												// group
		
		System.out.println("n = " + n);
		BigInteger r; // private key recovery data and CA ephemeral private key,respectively.
		BigInteger e; // Integer representation of H(Certu)
		BigInteger dCa = ((BCECPrivateKey) issuerPrivateKey).getD(); // Private (point multiplier) of the issuer
		ECPoint infinity = curveParameters.getCurve().getInfinity(); // The identity point.

		do {
			// create ephemeral key pair (k, kG)
			KeyPairGenerator keyGen = KeyPairGenerator.getInstance("ECDSA", BouncyCastleProvider.PROVIDER_NAME);
			keyGen.initialize(curveParameters, random);

			KeyPair caEphemeralKeyPair = keyGen.generateKeyPair();
			caEphemeralPrivateKey = (BCECPrivateKey) caEphemeralKeyPair.getPrivate();
			caEphemeralPublicKey = (BCECPublicKey) caEphemeralKeyPair.getPublic();
			System.out.println("k = " + caEphemeralPrivateKey.getD());
			System.out.println("kG = " + caEphemeralPublicKey.toString());

			// Compute Pu = Ru + kG
			// this is the reconstruction point
			p = ((BCECPublicKey) ephemeralPublicKey).getQ().add(caEphemeralPublicKey.getQ());			
			reconstructionPoint = p.getEncoded(true);
			System.out.println("Pu = Ru + kG = " + byte2HexStr(reconstructionPoint));
			cert = genCert(identifyingInfo, reconstructionPoint);			
			fullCertData = cert.getEncoded();
			//full cert
			System.out.println("fullCertData : "+byte2HexStr(fullCertData));	
			//full cert base64?
			System.out.println("fullCertData base64: "+org.bouncycastle.util.encoders.Base64.encode(fullCertData));
			for(byte b : fullCertData){
				digest.update(b);
			}
			// hash the implicit certificate Certu and compute the integer e
			// from H(Certu)
			e = calculateE(n, digest.digest()).mod(n);
			System.out.println("H(Certu) = " + byte2HexStr(digest.digest()));
			System.out.println("e = Hn(Certu) = " + e);

			// from sec4 S3.4
		} while (p.multiply(e).add(curveParameters.getG().multiply(dCa)).equals(infinity));

		// compute r = ek + dCA (mod n)
		r = e.multiply(caEphemeralPrivateKey.getD()).add(dCa).mod(n);
		System.out.println("r = ek + dCA (mod n) =  " + r);
		return new KeyReconstructionData(reconstructionPoint, integerToOctetString(r, n));
	}
	
	private static M2mCertificate genCert(byte[] UID, byte[] reconstructPu) throws IOException, InvalidKeyException, IllegalArgumentException, CertificateEncodingException, URISyntaxException{
		// Construct certificate data
		// A full certificate
		M2mCertificate cert = new M2mCertificate();

		// serialNumber
		byte[] serialNumber = Hex.decode("F964EF36");
		cert.setSerialNumber(serialNumber);

		// cAAlgorithm, CAAlgParams
		KeyAlgorithmDefinition caKeyDefinition = new KeyAlgorithmDefinition();
		caKeyDefinition.setAlgorithm(M2mSignatureAlgorithmOids.ECDSA_SHA512_SECP521R1);
//			caKeyDefinition.setAlgorithm(M2mSignatureAlgorithmOids.ECQV_SHA256_SECP256K1);
		caKeyDefinition.setParameters(Hex.decode("102030405060708090A0B0C0E0F0"));
		cert.setCaKeyDefinition(caKeyDefinition);

		// issuer
		EntityName issuer = new EntityName();
		issuer.addAttribute(new EntityNameAttribute(EntityNameAttributeId.Country, "CA"));
		issuer.addAttribute(new EntityNameAttribute(EntityNameAttributeId.CommonName, "MyRoot"));
		issuer.addAttribute(new EntityNameAttribute(EntityNameAttributeId.DomainComponent, "DomC"));
		issuer.addAttribute(new EntityNameAttribute(EntityNameAttributeId.OctetsName, "ca2f00"));
		cert.setIssuer(issuer);

		// validFrom
		Calendar calendar = new GregorianCalendar(2018, 1, 1);
		Date validFrom = calendar.getTime();
		cert.setValidFrom(validFrom);

		// validDuration
		cert.setValidDuration(60 * 60 * 24 * 365);

		// subject
		EntityName subject = new EntityName();
		subject.addAttribute(new EntityNameAttribute(EntityNameAttributeId.Country, "CA"));
		subject.addAttribute(new EntityNameAttribute(EntityNameAttributeId.CommonName, "MyTest"));
		subject.addAttribute(new EntityNameAttribute(EntityNameAttributeId.DomainComponent, "DomC"));
		subject.addAttribute(new EntityNameAttribute(EntityNameAttributeId.OctetsName, "ca2f01"));
		cert.setSubject(subject);

		// pKAlgorithm, pKAlgParams
		KeyAlgorithmDefinition publicKeyDefinition = new KeyAlgorithmDefinition();
		publicKeyDefinition.setAlgorithm(M2mSignatureAlgorithmOids.ECDSA_SHA256_SECP256R1);
		publicKeyDefinition.setParameters(Hex.decode("0102030405060708090A0B0C0E0F"));
		cert.setPublicKeyDefinition(publicKeyDefinition);

		// pubKey
		byte[] rawPublicKey = Hex.decode("040078EF059D605AB85B6A25A6EF31A1A73A632D3CB04DC606A8CA0B58239661"
				+ "68CFAF6131D8D9B53F6BDF6B62946EC4B41D618FA3FF7F8BBFACBFD4F64FE3C3"
				+ "3DA9D200A47AE528DC50B6F3876D7F5BA3C082D9927751E1A8C4F934D90942B3"
				+ "5C57DFE311B2663E8D0187AD4EDE31BF9CD2AD8317107360522FDB6975AB2CD6" + "6DC029981F");
		boolean isCompressed = KeyConversionUtils.isCompressedEcPoint(rawPublicKey);
		cert.setIsPublicKeyCompressed(isCompressed);

		PublicKey publicKey = KeyConversionUtils.convertRawBytestoEcPublicKey(rawPublicKey);
		cert.setPublicKey(publicKey);

		// authKeyId
		AuthorityKeyIdentifier authKeyId = new AuthorityKeyIdentifier();
		authKeyId.setKeyIdentifier(Hex.decode("793F0C56"));
		GeneralName authKeyIdIssuer = new GeneralName(GeneralNameAttributeId.DnsName, "authKeyIdIssuer");
		authKeyId.setCertificateIssuer(authKeyIdIssuer);
		authKeyId.setCertificateSerialNumber(new BigInteger(Hex.decode("729CB27DAE30")));
		cert.setAuthorityKeyIdentifier(authKeyId);

		// subjKeyId
		cert.setSubjectKeyIdentifier(Hex.decode("729CB27DAE31"));

		// keyUsage
		KeyUsage keyUsage = new KeyUsage();
		keyUsage.setDigitalSignature(true);
		cert.setKeyUsage(keyUsage);

		// basicConstraints
		cert.setBasicConstraints(5);

		// certificatePolicy
		cert.setCertificatePolicy("1.2.66.148.0.12");

		// subjectAltName
		GeneralName subjectAltName = new GeneralName(GeneralNameAttributeId.DnsName, "subjectAltName");
		cert.setSubjectAlternativeName(subjectAltName);

		// issuerAltName
		GeneralName issuerAltName = new GeneralName(GeneralNameAttributeId.DnsName, "issuerAltName");
		cert.setIssuerAlternativeName(issuerAltName);

		// extendedKeyUsage
		cert.setExtendedKeyUsage("1.3.22.174.22");

		// authInfoAccessOCSP
		URI authInfoAccessOCSP = new URI("https://ocsptest.trustpointinnovation.com");
		cert.setAuthenticationInfoAccessOcsp(authInfoAccessOCSP);

		// cRLDistribPointURI
		URI cRLDistribPointURI = new URI("https://ocsptest.trustpointinnovation.com");
		cert.setCrlDistributionPointUri(cRLDistribPointURI);

		// x509extensions
		String oid1 = "1.5.24.632.0";
		String oid2 = "1.5.24.632.1";
		byte[] value1 = Hex.decode("003a772fb1");
		byte[] value2 = Hex.decode("98f2b10e27");
		cert.addExtension(oid1, true, value1);
		cert.addExtension(oid2, false, value2);

		// cACalcValue
		byte[] caCalcValue = Hex.decode("3081880242014F15CAF8EF38626B2C7CFA85B9544E028668290CADB45F62E215"
				+ "3EAAF5A9D51AF5BF0D02F2C057D3856B5CBFB3529C25B8481405924039FA612D"
				+ "422AE9A1A85591024201868D3DFE5FC2BEDD2F7468B0B17ED2708E76CD0D37C4"
				+ "4F4D0BB88693752046FCFC56D9818B32533B8992923C2C81499400AC44FBBECD" + "6324D8AE1DD41EC73A0B2A");
		cert.setCaCalcValue(caCalcValue);

		// get encoded data
		fullCertData = cert.getEncoded();		
		System.out.println(byte2HexStr(fullCertData));

		int mySignerIndex = 0;
		int myIssuerIndex = 1;
		int bluelineIndex = 2;
		int certsTotal = 3;

		// construct certificate array
		ASN1Encodable[] certArray = new ASN1Encodable[certsTotal];
		certArray[mySignerIndex] = ASN1Primitive.fromByteArray(signerData);
		certArray[myIssuerIndex] = ASN1Primitive.fromByteArray(issuerData);
		certArray[bluelineIndex] = ASN1Primitive.fromByteArray(rootcaData);
		ASN1EncodableVector vCerts;

		// Construct PKI Path encoding input data
		vCerts = new ASN1EncodableVector();
		vCerts.add(certArray[bluelineIndex]);
		vCerts.add(certArray[myIssuerIndex]);
		vCerts.add(certArray[mySignerIndex]);
		pkiPathInputData = new DERSequence(vCerts).getEncoded();

		// Construct PKCS7 encoding input data
		ASN1EncodableVector vContentInfo = new ASN1EncodableVector();

		// contentType
		ASN1ObjectIdentifier contentType = PKCSObjectIdentifiers.data;
		vContentInfo.add(contentType);

		// content: signedData
		ASN1EncodableVector vSignedData = new ASN1EncodableVector();

		// version
		ASN1Integer sdVersion = new ASN1Integer(BigInteger.ONE);
		vSignedData.add(sdVersion);

		// digestAlgorithmIds
		DERSet sdDigestAlgorithmIds = new DERSet();
		vSignedData.add(sdDigestAlgorithmIds);

		// contentInfo without content
		BERSequence sdContentInfo = new BERSequence(PKCSObjectIdentifiers.data);
		vSignedData.add(sdContentInfo);

		// certificates [0] IMPLICIT SET OF certificate
		vCerts = new ASN1EncodableVector();
		vCerts.add(certArray[mySignerIndex]);
		vCerts.add(certArray[myIssuerIndex]);
		vCerts.add(certArray[bluelineIndex]);

		DERTaggedObject sdCertificates = new DERTaggedObject(false, 0, new DERSet(vCerts));
		vSignedData.add(sdCertificates);

		// signerInfos
		DERSet sdSignerInfos = new DERSet();
		vSignedData.add(sdSignerInfos);

		// content [0] EXPLICIT SEQUENCE signedData
		BERSequence signedData = new BERSequence(vSignedData);
		BERTaggedObject content = new BERTaggedObject(true, 0, signedData);
		vContentInfo.add(content);

		BERSequence contentInfo = new BERSequence(vContentInfo);
		pkcs7InputData = contentInfo.getEncoded();

		// Contruct cert path data list
		// Certificates are store in M2MCertPath from target to trust anchor.
		expectedCertPathData = new byte[][] { signerData, issuerData, rootcaData };
		return cert;	
	}
	
	/**
	 * Reconstruct the public key from the implicit certificate and the CA's
	 * public key
	 *
	 * @param identifyingInfo
	 *            the identity portion of the implicit certificate
	 * @param reconstructionPoint
	 *            the reconstruction point for the implicit certificate
	 * @param qCa
	 *            the CA's public key
	 *
	 * @return the public key reconstructed from the implicit certificate
	 *
	 * @throws IOException
	 *             errors in provided data
	 * @throws CertificateEncodingException 
	 */
	public PublicKey reconstructPublicKey(M2mCertificate cert, byte[] reconstructionPoint, PublicKey qCa)
			throws IOException, CertificateEncodingException {
		// Reconstruct the point Pu from the reconstruction point
		ECPoint rPoint = ((BCECPublicKey) BouncyCastleProvider
				.getPublicKey(new SubjectPublicKeyInfo(algorithmId, reconstructionPoint))).getQ();
		BigInteger n = curveParameters.getN(); // curve point order
		ECPoint caPoint = ((BCECPublicKey) qCa).getQ(); // Massage caPublicKey
														// bytes into ECPoint

		fullCertData = cert.getEncoded();
		for(byte b : fullCertData){
			digest.update(b);
		}
		// Hash the implicit certificate Certu and compute the integer e from
		// H(Certu)
		BigInteger e = calculateE(n, digest.digest()).mod(n);
		System.out.println("H(Certu) = " + byte2HexStr(digest.digest()));
		System.out.println("e = Hn(Certu) = " + e);

		// compute the point Qu = ePu + Qca
		SubjectPublicKeyInfo publicKeyInfo = new SubjectPublicKeyInfo(algorithmId,
				rPoint.multiply(e).add(caPoint).getEncoded(false));
		System.out.println("PublicKey = Qu = ePu + Qca = " + byte2HexStr(publicKeyInfo.getEncoded()));

		return BouncyCastleProvider.getPublicKey(publicKeyInfo);
	}

	/**
	 * Reconstruct the private key from the reconstruction data
	 *
	 * @param identifyingInfo
	 *            the identity portion of the implicit certificate
	 * @param reconstructionPoint
	 *            the reconstruction point for the implicit certificate
	 * @param privateKeyReconstructionData
	 *            the private key reconstruction data associated with the
	 *            implicit certificate
	 * @param ephemeralPrivateKey
	 *            the requesters ephemeral private key
	 *
	 * @return the private key associated with the implicit certificate
	 *
	 * @throws IOException
	 *             when there are errors with, or malformed provided data
	 * @throws CertificateEncodingException 
	 */
	public PrivateKey reconstructPrivateKey(M2mCertificate cert, byte[] reconstructionPoint,
			byte[] privateKeyReconstructionData, PrivateKey ephemeralPrivateKey) throws IOException, CertificateEncodingException {
		// curve point order
		BigInteger n = curveParameters.getN();

		fullCertData = cert.getEncoded();
		for(byte b : fullCertData){
			digest.update(b);
		}

		// compute the integer e from H(Certu)
		BigInteger e = calculateE(n, digest.digest()).mod(n);

		// compute the private Key dU = r + e*kU (mod n)
		BigInteger r = octetStringToInteger(privateKeyReconstructionData);
		System.out.println("r = " + r);

		// Check that the 'r' is less than 'n'
		if (n.compareTo(r) != 1) {
			throw new IOException("Octet String value is larger than modulus");
		}

		// Private key dU.
		BigInteger dU = ((BCECPrivateKey) ephemeralPrivateKey).getD();
		System.out.println("kU = " + dU);
		dU = e.multiply(dU);
		System.out.println("ekU = " + dU);
		dU = r.add(dU);
		dU = dU.mod(n);
		PrivateKeyInfo privateKeyInfo = new PrivateKeyInfo(algorithmId, new ASN1Integer(dU.toByteArray()));
		System.out.println("PrivateKey = dU = r + e*kU (mod n) = " + byte2HexStr(privateKeyInfo.getEncoded()));
		return BouncyCastleProvider.getPrivateKey(privateKeyInfo);
	}

	/**
	 * Confirm that derived public Key qU and derived private key dU satisfy: qU
	 * = dU*G where G is the base point for the curve.
	 *
	 * @param derivedPublicKey
	 *            the recovered public key
	 * @param derivedPrivateKey
	 *            the recovered private key
	 *
	 * @return true for successful confirmation, false otherwise
	 */
	public boolean verifyKeyPair(PublicKey derivedPublicKey, PrivateKey derivedPrivateKey) {
		// confirm equality
		System.out.println("verify QU = dU * G");
		System.out.println("QU = " + byte2HexStr(((BCECPublicKey) derivedPublicKey).getQ().getEncoded()));
		System.out.println("dU * G = " + byte2HexStr(
				curveParameters.getG().multiply(((BCECPrivateKey) derivedPrivateKey).getD()).getEncoded()));
		return (((BCECPublicKey) derivedPublicKey).getQ()
				.equals(curveParameters.getG().multiply(((BCECPrivateKey) derivedPrivateKey).getD())));
	}

	public PrivateKey genNewKey1(PrivateKey t, PublicKey T, PublicKey Qu, PrivateKey du, M2mCertificate cert,
			byte[] reconstructionPoint) throws IOException, CertificateEncodingException {
		
		BigInteger n = curveParameters.getN();
		BigInteger e, newe, newdA; // Integer representation of H(Certu)
		// User's additional ephemeral key pair (t, tG(T))
		BCECPublicKey TEphemeralPub = (BCECPublicKey) T;
		BCECPrivateKey tEphemeralPri = (BCECPrivateKey) t;
		BigInteger duInt = ((BCECPrivateKey) du).getD();
		fullCertData = cert.getEncoded();
		for(byte b : fullCertData){
			digest.update(b);
		}
		e = calculateE(n, digest.digest()).mod(n);
		System.out.println("e : " + e);
		
		byte[] ebyte = e.toByteArray();
		
		for (byte b : ebyte) {
			m1newdigest.update(b);
		}
		
		byte[] Tbyte = ((BCECPublicKey) T).getQ().getEncoded();
		for (byte b : Tbyte) {
			m1newdigest.update(b);
		}
		
		byte[] Qubyte = ((BCECPublicKey) Qu).getQ().getEncoded();
		System.out.println("===========");
		for (byte b : Qubyte) {
			m1newdigest.update(b);
		}
		
		newe = calculateE(n, m1newdigest.digest()).mod(n);
		
		System.out.println("e' : " + newe);
		newdA = newe.multiply(tEphemeralPri.getD()).add(duInt).mod(n);
		return BouncyCastleProvider
				.getPrivateKey(new PrivateKeyInfo(algorithmId, new ASN1Integer(newdA.toByteArray())));
	}

	public PublicKey verifyNewKey1(M2mCertificate cert, PublicKey T, PublicKey Qca, byte[] reconstructionPoint)
			throws IOException, CertificateEncodingException {
		BigInteger n = curveParameters.getN();
		BigInteger be, bnewe;
		fullCertData = cert.getEncoded();
		for(byte b : fullCertData){
			bdigest.update(b);
		}		
		be = calculateE(n, bdigest.digest()).mod(n);
		System.out.println("B e : " + be);
		ECPoint puPoint = ((BCECPublicKey) BouncyCastleProvider
				.getPublicKey(new SubjectPublicKeyInfo(algorithmId, reconstructionPoint))).getQ();
		ECPoint caPoint = ((BCECPublicKey) Qca).getQ();
		SubjectPublicKeyInfo publicKeyInfo = new SubjectPublicKeyInfo(algorithmId,
				puPoint.multiply(be).add(caPoint).getEncoded(false));
		PublicKey Qu = BouncyCastleProvider.getPublicKey(publicKeyInfo);
		byte[] ebyte = be.toByteArray();
		for (byte b : ebyte) {
			bm1newdigest.update(b);
		}
		byte[] Tbyte = ((BCECPublicKey) T).getQ().getEncoded();
		for (byte b : Tbyte) {
			bm1newdigest.update(b);
		}
		byte[] Qubyte = ((BCECPublicKey) Qu).getQ().getEncoded();
		for (byte b : Qubyte) {
			bm1newdigest.update(b);
		}
		bnewe = calculateE(n, bm1newdigest.digest()).mod(n);
		System.out.println("B e' : " + bnewe);
		ECPoint tPoint = ((BCECPublicKey) T).getQ();
		ECPoint quPoint = ((BCECPublicKey) Qu).getQ();
		SubjectPublicKeyInfo newpublicKeyInfo = new SubjectPublicKeyInfo(algorithmId,
				tPoint.multiply(bnewe).add(quPoint).getEncoded(false));
		return BouncyCastleProvider.getPublicKey(newpublicKeyInfo);
	}

	public BigInteger genNewKey2(PrivateKey t, PublicKey T, PublicKey Qu, PrivateKey du, M2mCertificate cert) throws IOException, CertificateEncodingException {
		BigInteger n = curveParameters.getN();
		BigInteger e, newe, newdA, c, z; // Integer representation of H(Certu)
		// User's additional ephemeral key pair (t, tG(T))
		BCECPublicKey TEphemeralPub = (BCECPublicKey) T;
		BCECPrivateKey tEphemeralPri = (BCECPrivateKey) t;
		BigInteger duInt = ((BCECPrivateKey) du).getD();
		fullCertData = cert.getEncoded();
		for(byte b : fullCertData){
			digest.update(b);
		}	
		e = calculateE(n, digest.digest()).mod(n);
//		System.out.println("e : " + e);
		byte[] ebyte = e.toByteArray();
		for (byte b : ebyte) {
			m2newdigest.update(b);
		}
		byte[] Tbyte = TEphemeralPub.getQ().getEncoded();
		for (byte b : Tbyte) {
			m2newdigest.update(b);
		}
		byte[] Qubyte = ((BCECPublicKey) Qu).getQ().getEncoded();
		for (byte b : Qubyte) {
			m2newdigest.update(b);
		}
		newe = calculateE(n, m2newdigest.digest()).mod(n);
		newdA = newe.multiply(tEphemeralPri.getD()).add(duInt).mod(n);
		PrivateKey newdu = BouncyCastleProvider
				.getPrivateKey(new PrivateKeyInfo(algorithmId, new ASN1Integer(newdA.toByteArray())));
		PublicKey newdQu = getPubFromPri(newdu);
		byte[] newebyte = newe.toByteArray();
		for (byte b : newebyte) {
			cdigest.update(b);
		}
		for (byte b : Tbyte) {
			cdigest.update(b);
		}
		byte[] newQubyte = ((BCECPublicKey) newdQu).getQ().getEncoded();
		for (byte b : newQubyte) {
			cdigest.update(b);
		}
		c = calculateE(n, cdigest.digest()).mod(n);
		System.out.println("c : " + c);
		z = c.multiply(duInt).add(tEphemeralPri.getD());
		return z;
	}

	public Boolean verifyNewKey2(BigInteger z, M2mCertificate cert, PublicKey T, PublicKey Qca, byte[] reconstructionPoint)
			throws IOException, CertificateEncodingException {
		BigInteger n = curveParameters.getN();
		BigInteger be, bnewe, bc;
		fullCertData = cert.getEncoded();
		for(byte b : fullCertData){
			bdigest.update(b);
		}	
		be = calculateE(n, bdigest.digest()).mod(n);
		System.out.println("B e : " + be);
		ECPoint puPoint = ((BCECPublicKey) BouncyCastleProvider
				.getPublicKey(new SubjectPublicKeyInfo(algorithmId, reconstructionPoint))).getQ();
		ECPoint caPoint = ((BCECPublicKey) Qca).getQ();
		SubjectPublicKeyInfo publicKeyInfo = new SubjectPublicKeyInfo(algorithmId,
				puPoint.multiply(be).add(caPoint).getEncoded(false));
		PublicKey Qu = BouncyCastleProvider.getPublicKey(publicKeyInfo);
		byte[] ebyte = be.toByteArray();
		for (byte b : ebyte) {
			bm2newdigest.update(b);
		}
		byte[] Tbyte = ((BCECPublicKey) T).getQ().getEncoded();
		for (byte b : Tbyte) {
			bm2newdigest.update(b);
		}
		byte[] Qubyte = ((BCECPublicKey) Qu).getQ().getEncoded();
		for (byte b : Qubyte) {
			bm2newdigest.update(b);
		}
		bnewe = calculateE(n, bm2newdigest.digest()).mod(n);
		System.out.println("B e' : " + bnewe);
		ECPoint tPoint = ((BCECPublicKey) T).getQ();
		ECPoint quPoint = ((BCECPublicKey) Qu).getQ();
		SubjectPublicKeyInfo newpublicKeyInfo = new SubjectPublicKeyInfo(algorithmId,
				tPoint.multiply(bnewe).add(quPoint).getEncoded(false));
		PublicKey newQu = BouncyCastleProvider.getPublicKey(newpublicKeyInfo);
		System.out.println("New PublicKey  : "+byte2HexStr(newQu.getEncoded()));
		byte[] newebyte = bnewe.toByteArray();
		for (byte b : newebyte) {
			bcdigest.update(b);
		}
		for (byte b : Tbyte) {
			bcdigest.update(b);
		}
		byte[] newQubyte = ((BCECPublicKey) newQu).getQ().getEncoded();
		for (byte b : newQubyte) {
			bcdigest.update(b);
		}
		bc = calculateE(n, bcdigest.digest()).mod(n);
		System.out.println("B c : " + bc);
		SubjectPublicKeyInfo newVerifyInfo = new SubjectPublicKeyInfo(algorithmId,
				curveParameters.getG().multiply(z).getEncoded(false));
		SubjectPublicKeyInfo newVerifyInfo2 = new SubjectPublicKeyInfo(algorithmId,
				quPoint.multiply(bc).add(tPoint).getEncoded(false));
		PublicKey pub1 = BouncyCastleProvider.getPublicKey(newVerifyInfo);
		PublicKey pub2 = BouncyCastleProvider.getPublicKey(newVerifyInfo2);
		System.out.println("zG : " + byte2HexStr(pub1.getEncoded()));
		System.out.println("T+cQu : " + byte2HexStr(pub2.getEncoded()));
		return BouncyCastleProvider.getPublicKey(newVerifyInfo)
				.equals(BouncyCastleProvider.getPublicKey(newVerifyInfo2));
		// return newVerifyInfo.equals(newVerifyInfo2);
	}
	
	
	
	
	//overload this function
	public Boolean verifyNewKey2(BigInteger z, String cert, String T, PublicKey Qca, byte[] reconstructionPoint)
			throws IOException, CertificateEncodingException {
		BigInteger n = curveParameters.getN();
		BigInteger be, bnewe, bc;
		//
		System.out.println("---in vernewkey2---");
		//
		fullCertData = HexStr2byte(cert);
		for(byte b : fullCertData){
			bdigest.update(b);
		}	
		be = calculateE(n, bdigest.digest()).mod(n);
		System.out.println("B e : " + be);
		ECPoint puPoint = ((BCECPublicKey) BouncyCastleProvider
				.getPublicKey(new SubjectPublicKeyInfo(algorithmId, reconstructionPoint))).getQ();
		ECPoint caPoint = ((BCECPublicKey) Qca).getQ();
		SubjectPublicKeyInfo publicKeyInfo = new SubjectPublicKeyInfo(algorithmId,
				puPoint.multiply(be).add(caPoint).getEncoded(false));
		PublicKey Qu = BouncyCastleProvider.getPublicKey(publicKeyInfo);
		byte[] ebyte = be.toByteArray();
		for (byte b : ebyte) {
			bm2newdigest.update(b);
		}
		//byte[] Tbyte = ((BCECPublicKey) T).getQ().getEncoded();
		byte[] Tbyte = HexStr2byte(T);
		for (byte b : Tbyte) {
			bm2newdigest.update(b);
		}
		byte[] Qubyte = ((BCECPublicKey) Qu).getQ().getEncoded();
		for (byte b : Qubyte) {
			bm2newdigest.update(b);
		}
		bnewe = calculateE(n, bm2newdigest.digest()).mod(n);
		System.out.println("B e' : " + bnewe);
		//ECPoint tPoint = ((BCECPublicKey) T).getQ();
		ECPoint tPoint = ((BCECPublicKey) Qu).getQ();
		ECPoint quPoint = ((BCECPublicKey) Qu).getQ();
		SubjectPublicKeyInfo newpublicKeyInfo = new SubjectPublicKeyInfo(algorithmId,
				tPoint.multiply(bnewe).add(quPoint).getEncoded(false));
		PublicKey newQu = BouncyCastleProvider.getPublicKey(newpublicKeyInfo);
		System.out.println("New PublicKey  : "+byte2HexStr(newQu.getEncoded()));
		byte[] newebyte = bnewe.toByteArray();
		for (byte b : newebyte) {
			bcdigest.update(b);
		}
		for (byte b : Tbyte) {
			bcdigest.update(b);
		}
		byte[] newQubyte = ((BCECPublicKey) newQu).getQ().getEncoded();
		for (byte b : newQubyte) {
			bcdigest.update(b);
		}
		bc = calculateE(n, bcdigest.digest()).mod(n);
		System.out.println("B c : " + bc);
		SubjectPublicKeyInfo newVerifyInfo = new SubjectPublicKeyInfo(algorithmId,
				curveParameters.getG().multiply(z).getEncoded(false));
		SubjectPublicKeyInfo newVerifyInfo2 = new SubjectPublicKeyInfo(algorithmId,
				quPoint.multiply(bc).add(tPoint).getEncoded(false));
		PublicKey pub1 = BouncyCastleProvider.getPublicKey(newVerifyInfo);
		PublicKey pub2 = BouncyCastleProvider.getPublicKey(newVerifyInfo2);
		System.out.println("zG : " + byte2HexStr(pub1.getEncoded()));
		System.out.println("T+cQu : " + byte2HexStr(pub2.getEncoded()));
		return BouncyCastleProvider.getPublicKey(newVerifyInfo)
				.equals(BouncyCastleProvider.getPublicKey(newVerifyInfo2));
		// return newVerifyInfo.equals(newVerifyInfo2);
	}
	
	
	

	public PublicKey getPubFromPri(PrivateKey pri) throws IOException {

		ECPoint pub = curveParameters.getG().multiply(((BCECPrivateKey) pri).getD());
		SubjectPublicKeyInfo publicKeyInfo = new SubjectPublicKeyInfo(algorithmId, pub.getEncoded(false));

		return BouncyCastleProvider.getPublicKey(publicKeyInfo);
	}

	/**
	 * Compute the integer e from H(Certu)
	 *
	 * @param n
	 *            Curve order.
	 * @param messageDigest
	 *            Message digest.
	 * @return e value.
	 */
	private BigInteger calculateE(BigInteger n, byte[] messageDigest) {
		// n.bitLength() == ceil(log2(n < 0 ? -n : n+1)
		// we actually want floor(log_2(n)) which is n.bitLength()-1
		int log2n = n.bitLength() - 1;
		int messageBitLength = messageDigest.length * 8;

		if (log2n >= messageBitLength) {
			return new BigInteger(1, messageDigest);
		} else {
			BigInteger trunc = new BigInteger(1, messageDigest);

			trunc = trunc.shiftRight(messageBitLength - log2n);

			return trunc;
		}
	}

	/**
	 * Convert an octet string to a {@link java.math.BigInteger BigInteger}.
	 *
	 * @param os
	 *            the octet string
	 * @return The {@link java.math.BigInteger BigInteger} value.
	 */
	private BigInteger octetStringToInteger(byte[] os) {
		int osLen = os.length;
		byte[] osSigned;

		// Always prepend 0x00 byte to make it positive signed integer
		// (instead of checking the length of 'os' & 'modulus')
		osSigned = new byte[osLen + 1];
		System.arraycopy(os, 0, osSigned, 1, osLen);
		return new BigInteger(osSigned);
	}

	/**
	 * Converts the given integer value and the given modulus to an octet
	 * string.
	 *
	 * @param r
	 *            Integer value to convert.
	 * @param modulus
	 *            Modulus to convert.
	 * @return Octet string representing r and modulus.
	 * @throws IOException
	 *             if r is greater than modulus.
	 */
	private byte[] integerToOctetString(BigInteger r, BigInteger modulus) throws IOException {
		byte[] modulusBytes = modulus.toByteArray();
		int modulusLen = modulusBytes.length;
		byte[] rBytes = r.toByteArray();
		int rLen = rBytes.length;
		int rMSB = rBytes[0] & 0xFF;

		if (modulusBytes[0] == 0x00) {
			modulusLen -= 1;
		}

		// for arrays that are more than one byte longer
		if ((rLen == modulusLen + 1 && rMSB != 0x00) || rLen > modulusLen + 1) {
			throw new IOException("Integer value is larger than modulus");
		}

		byte[] rUnsigned = new byte[modulusLen];
		System.arraycopy(rBytes, (rLen > modulusLen) ? (rLen - modulusLen) : 0, rUnsigned,
				(modulusLen > rLen) ? (modulusLen - rLen) : 0, (modulusLen > rLen) ? rLen : modulusLen);

		return rUnsigned;
	}

	
	
	private static String byte2HexStr(byte[] a) {
		StringBuilder sb = new StringBuilder(a.length * 2);
		for (byte b : a)
			sb.append(String.format("%02x", b & 0xff));
		return sb.toString().toUpperCase();
		
	}

	//add this function
	private static byte[] HexStr2byte(String hex) {
		/*
		int len = (hex.length() / 2);
		byte[] result = new byte[len];
		char[] achar = hex.toCharArray();
 
		for (int i = 0; i < len; i++)
		{
			int pos = i * 2;
			result[i] = (byte) (toByte(achar[pos]) << 4 | toByte(achar[pos + 1]));
		}
		return result;*/
		byte[] b = hex.getBytes();
		System.out.println("---in hex2byte---");
		for(byte bb:b){
			System.out.print(bb);
		}
		return b;
	}
	
	public static byte[] getFullCertData() {
		return fullCertData;
	}

	public static void setFullCertData(byte[] fullCertData) {
		EcqvProvider2.fullCertData = fullCertData;
	}
	
	
}
