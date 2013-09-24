package com.example.simplesms;

import org.bouncycastle.crypto.AsymmetricCipherKeyPair;
import org.bouncycastle.crypto.CipherParameters;
import org.bouncycastle.crypto.params.ECDomainParameters;
import org.bouncycastle.crypto.params.ECPrivateKeyParameters;
import org.thoughtcrime.securesms.crypto.AsymmetricMasterSecret;
import org.thoughtcrime.securesms.crypto.KeyUtil;
import org.thoughtcrime.securesms.crypto.MasterSecret;
import org.thoughtcrime.securesms.crypto.MasterSecretUtil;
import org.thoughtcrime.securesms.crypto.PublicKey;

import android.os.Bundle;
import android.app.Activity;
import android.util.Log;
import android.view.Menu;

public class MainActivity extends Activity {
	// debugging
	private final String TAG = "MainActivity";

	@Override
	protected void onCreate(Bundle savedInstanceState) {
		super.onCreate(savedInstanceState);
		setContentView(R.layout.activity_main);

		// TODO create the pair of private key & public key based on a
		// passphrase and something random
		String passphrase = "hardcodepassphrase";
		MasterSecret masterSecret = MasterSecretUtil.generateMasterSecret(
				getApplicationContext(), passphrase);

		AsymmetricMasterSecret secretPair = MasterSecretUtil.generateAsymmetricMasterSecret(
				getApplicationContext(), masterSecret);
		PublicKey publicKey = secretPair.getPublicKey();
		ECPrivateKeyParameters privateKey = secretPair.getPrivateKey();
		String publicKeyString = new String(publicKey.serialize());
		Log.w(TAG, "public key is "+publicKeyString);
		
		//IdentityKeyUtil.generateIdentityKeys(getApplicationContext(),masterSecret);

		// TODO to send the public key send via sms

		// TODO to encrypt a message using the private key and send via sms &
		// send a digital signature

	}

	@Override
	public boolean onCreateOptionsMenu(Menu menu) {
		// Inflate the menu; this adds items to the action bar if it is present.
		getMenuInflater().inflate(R.menu.main, menu);
		return true;
	}

}
