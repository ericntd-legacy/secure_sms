package com.example.simplesms;

import java.math.BigInteger;
import java.security.InvalidKeyException;
import java.security.KeyFactory;
import java.security.NoSuchAlgorithmException;
import java.security.PublicKey;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.RSAPrivateKeySpec;
import java.security.spec.RSAPublicKeySpec;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;

import android.content.Context;
import android.content.SharedPreferences;
import android.util.Base64;
import android.util.Log;

public class MyKeyUtils {
	// debugging
	private static final String TAG = "MyKeyUtils";

	// sharedpreferences
	private static final String PREFS = "MyKeys";
	private final String PREFS_RECIPIENT = "RecipientsKeys";

	private static final String PREF_PUBLIC_MOD = "PublicModulus";
	private static final String PREF_PUBLIC_EXP = "PublicExponent";
	private static final String PREF_PRIVATE_MOD = "PrivateModulus";
	private static final String PREF_PRIVATE_EXP = "PrivateExponent";

	private static final String DEFAULT_PREF = "";
	private final String DEFAULT_RECIPIENT_NUM = "93628809";

	private final String PREF_RECIPIENT_NUM = "RecipientNum";

	protected static RSAPublicKeySpec getPublicKeySpec(Context context) {
		SharedPreferences prefs = context.getSharedPreferences(PREFS,
				Context.MODE_PRIVATE);

		String pubMod = prefs.getString(PREF_PRIVATE_MOD, DEFAULT_PREF);
		String pubExp = prefs.getString(PREF_PRIVATE_EXP, DEFAULT_PREF);
		// String recipient = prefs.getString(PREF_RECIPIENT_NUM, DEFAULT_PREF);
		if (!pubMod.equals(DEFAULT_PREF) && !pubExp.equals(DEFAULT_PREF)) {
			byte[] pubModBA = Base64.decode(pubMod, Base64.DEFAULT);
			byte[] pubExpBA = Base64.decode(pubExp, Base64.DEFAULT);
			BigInteger pubModBI = new BigInteger(pubModBA);
			BigInteger pubExpBI = new BigInteger(pubExpBA);

			RSAPublicKeySpec pubKeySpec = new RSAPublicKeySpec(pubModBI,
					pubExpBI);

			return pubKeySpec;
		} else
			return null;
	}
	
	protected static byte[] encryptMsg(String msg, RSAPublicKeySpec pubKeySpec) {
		try {
			KeyFactory fact = KeyFactory.getInstance("RSA");

			PublicKey pubKey = fact.generatePublic(pubKeySpec);

			// TODO encrypt the message and send it
			Cipher cipher = Cipher.getInstance("RSA");
			cipher.init(Cipher.ENCRYPT_MODE, pubKey);
			byte[] msgByteArray = msg.getBytes();
			byte[] cipherData = cipher.doFinal(msgByteArray);

			return cipherData;

		} catch (NoSuchAlgorithmException e) {
			Log.e(TAG, "RSA algorithm not available", e);
		} catch (InvalidKeySpecException e) {
			Log.e(TAG, "", e);
		} catch (NoSuchPaddingException e) {
			Log.e(TAG, "", e);
		} catch (InvalidKeyException e) {
			Log.e(TAG, "", e);
		} catch (BadPaddingException e) {
			Log.e(TAG, "", e);
		} catch (IllegalBlockSizeException e) {
			Log.e(TAG, "", e);
		}
		return null;
	}

}
