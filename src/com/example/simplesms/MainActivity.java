package com.example.simplesms;

import java.io.BufferedOutputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.ObjectOutputStream;
import java.math.BigInteger;
import java.security.InvalidKeyException;
import java.security.Key;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.PublicKey;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.RSAPrivateKeySpec;
import java.security.spec.RSAPublicKeySpec;
import java.util.ArrayList;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;

import android.os.Bundle;
import android.os.IBinder;
import android.app.Activity;
import android.app.PendingIntent;
import android.content.BroadcastReceiver;
import android.content.ComponentName;
import android.content.Context;
import android.content.Intent;
import android.content.IntentFilter;
import android.content.ServiceConnection;
import android.content.SharedPreferences;
import android.telephony.SmsManager;
import android.text.method.ScrollingMovementMethod;
import android.util.Log;
import android.view.Menu;
import android.view.View;
import android.view.View.OnClickListener;
import android.view.inputmethod.InputMethodManager;
import android.widget.Button;
import android.widget.EditText;
import android.widget.TextView;
import android.widget.Toast;

//import org.apache.commons.codec.binary.Base64;
import android.util.Base64;

public class MainActivity extends Activity {
	// debugging
	private final String TAG = "MainActivity";
	private final boolean D = true;
	private final boolean RESET = false;
	private TextView debugMessages;

	// sharedpreferences
	private final String PREFS = "MyKeys";
	private final String PREFS_RECIPIENT = "RecipientsKeys";

	private final String PREF_PUBLIC_MOD = "PublicModulus";
	private final String PREF_PUBLIC_EXP = "PublicExponent";
	private final String PREF_PRIVATE_MOD = "PrivateModulus";
	private final String PREF_PRIVATE_EXP = "PrivateExponent";

	private final String DEFAULT_PREF = "";
	private final String DEFAULT_RECIPIENT_NUM = "93628809";

	private final String PREF_RECIPIENT_NUM = "RecipientNum";

	// intents
	private final String INTENT_SOURCE = "Source";

	// others
	private final String DES_NUM = "93628809";

	// SMS codes
	private final String KEYX = "keyx";
	private final String HEALTH_SMS = "gmstelehealth";

	@Override
	protected void onCreate(Bundle savedInstanceState) {
		super.onCreate(savedInstanceState);
		setContentView(R.layout.activity_main);

		Log.i(TAG, "onCreate");
		
		debugMessages = (TextView) findViewById(R.id.DebugMessages);
		debugMessages.setMovementMethod(new ScrollingMovementMethod());

		// for testing only, clearing the SharedPreferences
		if (RESET) {
			Log.w(TAG,
					"TESTING - INTENDED RECIPIENT - Resetting the intended recipient's keys");
			SharedPreferences prefs = getSharedPreferences(PREFS_RECIPIENT,
					Context.MODE_PRIVATE);
			SharedPreferences.Editor prefsEditor = prefs.edit();

			prefsEditor.clear();
			prefsEditor.commit();
		}

		// TODO process the intent if any
		Intent intent = getIntent();
		if (intent != null) {
			Log.i(TAG,
					"activity launched by some intent from "
							+ intent.getStringExtra(INTENT_SOURCE));
		}

		/*
		 * Initilise the onClickListeners for the buttons
		 */
		initialiseOnClickListeners();

		/*
		 * Check if keys are found in the app's SharedPreferences if not,
		 * generate them and save them to the app's SharedPreferences
		 */
		// handleKeys();

		/*
		 * Handle the intended recipient's keys for testing
		 */
		//handleRecipientsKeys();

		// TODO to bind the activity to SendReceiveService
		// doBindService();

		// TODO to send the public key send via sms
		// SharedPreferences prefs = getSharedPreferences(PREFS,
		// Context.MODE_PRIVATE);
		// SmsManager smsManager = SmsManager.getDefault();

		/*
		 * String scAddress = null; Intent it = new
		 * Intent(SendReceiveService.SENT_SMS_ACTION, null,
		 * getApplicationContext(), SendReceiveService.class);
		 * it.putExtra(INTENT_SOURCE, "self"); PendingIntent sentIntent =
		 * PendingIntent.getBroadcast(getApplicationContext(), 0, it, 0);
		 * PendingIntent deliveredIntent = null;
		 */
		// Log.i(TAG, "sending public key modulus " + publicModString +
		// " to "+phoneNum);
		// smsManager.sendTextMessage(phoneNum, scAddress, publicModString,
		// sentIntent, deliveredIntent);

		// TODO to integrate the encryption to Kong SMS app and send the SMS via
		// such app instead of sending it directly here

		// TODO to encrypt a message using the private key and send via sms &
		// send a digital signature

		registerReceivers();

		String message = "gmstelehealth @systolic=100@ @diastolic=70@ @hr=70@";
		//sendEncryptedMessage(message);

	}

	@Override
	public boolean onCreateOptionsMenu(Menu menu) {
		// Inflate the menu; this adds items to the action bar if it is present.
		getMenuInflater().inflate(R.menu.main, menu);
		return true;
	}

	@Override
	public void onStart() {
		super.onStart();
		Log.i(TAG, "onStart");
	}

	@Override
	public void onResume() {
		super.onResume();
		Log.i(TAG, "onResume");
	}

	@Override
	public void onPause() {
		super.onPause();
		Log.i(TAG, "onPause");
	}

	@Override
	public void onDestroy() {
		Log.i(TAG, "onDestroy");
		//doUnbindService();
		super.onDestroy();
	}

	public void saveToFile(String fileName, BigInteger mod, BigInteger exp)
			throws IOException {
		ObjectOutputStream oout = new ObjectOutputStream(
				new BufferedOutputStream(new FileOutputStream(fileName)));
		try {
			oout.writeObject(mod);
			oout.writeObject(exp);
		} catch (Exception e) {
			throw new IOException("Unexpected error", e);
		} finally {
			oout.close();
		}
	}

	public void saveToPref(String pref, BigInteger num) {
		String st = new String(num.toByteArray());

		// Log.i(TAG, "modulus/ exponent length in bytes is " + st.length());
		SharedPreferences prefs = getSharedPreferences(PREFS,
				Context.MODE_PRIVATE);
		SharedPreferences.Editor prefsEditor = prefs.edit();

		prefsEditor.putString(pref, st);
		// prefsEditor.putString(PREF_PRIVATE_MOD, DEFAULT_PRIVATE_MOD);
		prefsEditor.commit();

		// Log.i(TAG, prefs.getString(pref, DEFAULT_PREF) +
		// " was successfully stored as "+pref );
	}

	private SendReceiveService mBoundService;

	private ServiceConnection mConnection = new ServiceConnection() {
		public void onServiceConnected(ComponentName className, IBinder service) {
			Log.i(TAG, "Activitiy bound to " + className.toString()
					+ " using binder " + service.toString());
			// This is called when the connection with the service has been
			// established, giving us the service object we can use to
			// interact with the service. Because we have bound to a explicit
			// service that we know is running in our own process, we can
			// cast its IBinder to a concrete class and directly access it.
			mBoundService = ((SendReceiveService.LocalBinder) service)
					.getService();

			// Tell the user about this for our demo.
			// Toast.makeText(MainActivity.this, "sendreceiveservice connected",
			// Toast.LENGTH_SHORT).show();
		}

		public void onServiceDisconnected(ComponentName className) {
			// This is called when the connection with the service has been
			// unexpectedly disconnected -- that is, its process crashed.
			// Because it is running in our same process, we should never
			// see this happen.
			/*
			 * mBoundService = null; Toast.makeText(Binding.this,
			 * R.string.local_service_disconnected, Toast.LENGTH_SHORT).show();
			 */
		}
	};

	private boolean mIsBound = false;

	private void doBindService() {
		Log.i(TAG, "binding the activity to SendReceiveService");
		// Establish a connection with the service. We use an explicit
		// class name because we want a specific service implementation that
		// we know will be running in our own process (and thus won't be
		// supporting component replacement by other applications).
		Intent intent = new Intent(MainActivity.this, SendReceiveService.class);
		intent.putExtra(INTENT_SOURCE, "MainActivity");
		bindService(intent, mConnection, Context.BIND_AUTO_CREATE);
		mIsBound = true;
	}

	private void doUnbindService() {
		Log.i(TAG, "unbinding the activity from SendReceiveService");
		if (mIsBound) {
			// Detach our existing connection.
			unbindService(mConnection);
			mIsBound = false;
		}
	}

	public void sendLongSMS(String phoneNum, String message) {
		String SENT = "SMS_SENT";
		String DELIVERED = "SMS_DELIVERED";
		SmsManager sm = SmsManager.getDefault();
		ArrayList<String> parts = sm.divideMessage(message);

		int numParts = parts.size();

		ArrayList<PendingIntent> sentIntents = new ArrayList<PendingIntent>();
		ArrayList<PendingIntent> deliveryIntents = new ArrayList<PendingIntent>();

		for (int i = 0; i < numParts; i++) {
			sentIntents.add(PendingIntent.getBroadcast(getApplicationContext(),
					0, new Intent(SENT), 0));
			deliveryIntents.add(PendingIntent.getBroadcast(
					getApplicationContext(), 0, new Intent(DELIVERED), 0));
		}

		sm.sendMultipartTextMessage(phoneNum, null, parts, sentIntents,
				deliveryIntents);
	}

	public void sendSMS(String phoneNum, String message) {
		String SENT = "SMS_SENT";
		String DELIVERED = "SMS_DELIVERED";

		PendingIntent sentPI = PendingIntent.getBroadcast(this, 0, new Intent(
				SENT), 0);

		PendingIntent deliveredPI = PendingIntent.getBroadcast(this, 0,
				new Intent(DELIVERED), 0);

		SmsManager sms = SmsManager.getDefault();
		sms.sendTextMessage(phoneNum, null, message, sentPI, deliveredPI);
	}

	/*
	 * Check if keys are found in the app's SharedPreferences if not, generate
	 * them and save them to the app's SharedPreferences
	 */
	private void handleKeys() {

		SharedPreferences prefs = getSharedPreferences(PREFS,
				Context.MODE_PRIVATE);
		String pubMod = prefs.getString(PREF_PUBLIC_MOD, DEFAULT_PREF);
		String pubExp = prefs.getString(PREF_PUBLIC_EXP, DEFAULT_PREF);
		String privateMod = prefs.getString(PREF_PRIVATE_MOD, DEFAULT_PREF);
		String privateExp = prefs.getString(PREF_PRIVATE_EXP, DEFAULT_PREF);

		boolean keysExist = false;

		if (!pubMod.equals(DEFAULT_PREF) && !pubExp.equals(DEFAULT_PREF)
				&& !privateMod.equals(DEFAULT_PREF)
				&& !privateExp.equals(DEFAULT_PREF)) {
			Log.i(TAG, "keys found, not regenerating");
			keysExist = true;
		} else {

			keysExist = false;
		}
		if (!keysExist) {
			Log.i(TAG, "keys not found, generating now");
			try {

				/*
				 * Generating private and public key using RSA algorithm saving
				 * the keys to the app's shared preferences
				 */
				KeyPairGenerator kpg = KeyPairGenerator.getInstance("RSA");
				kpg.initialize(2048);
				KeyPair kp = kpg.genKeyPair();
				Key publicKey = kp.getPublic();
				Key privateKey = kp.getPrivate();

				KeyFactory fact = KeyFactory.getInstance("RSA");
				RSAPublicKeySpec pub = fact.getKeySpec(publicKey,
						RSAPublicKeySpec.class);
				RSAPrivateKeySpec priv = fact.getKeySpec(privateKey,
						RSAPrivateKeySpec.class);

				/*
				 * save the public key to the app's SharedPreferences
				 */
				savePublicKey(pub);
				/*
				 * save the private key to the app's SharedPreferences
				 */
				savePrivateKey(priv);

			} catch (NoSuchAlgorithmException e) {
				Log.e(TAG, "RSA algorithm not available", e);
			} catch (InvalidKeySpecException e) {
				Log.e(TAG, "", e);
			}
			/*
			 * catch (IOException e) { Log.e(TAG,
			 * "Having trouble saving key file", e); }
			 */
		} else {
			byte[] myPubModBA = Base64.decode(pubMod, Base64.DEFAULT);
			byte[] myPubExpBA = Base64.decode(pubExp, Base64.DEFAULT);
			byte[] myPrivateModBA = Base64.decode(privateMod, Base64.DEFAULT);
			byte[] myPrivateExpBA = Base64.decode(privateExp, Base64.DEFAULT);

			BigInteger myPubModBI = new BigInteger(myPubModBA);
			BigInteger myPubExpBI = new BigInteger(myPubExpBA);

			BigInteger myPrivateModBI = new BigInteger(myPrivateModBA);
			BigInteger myPrivateExpBI = new BigInteger(myPrivateExpBA);

			Log.i(TAG, "the current user's stored public key modulus is "
					+ myPubModBI + " while the exponent is " + myPubExpBI
					+ " === private key modulus is " + myPrivateModBI
					+ " and exponent is " + myPrivateExpBI);
			TextView debug = (TextView) findViewById(R.id.DebugMessages);
			debug.append("Keys exist, not generating");
		}

	}

	/*
	 * 
	 */

	public void handleRecipientsKeys() {
		SharedPreferences prefs = getSharedPreferences(PREFS_RECIPIENT,
				Context.MODE_PRIVATE);
		String pubModRecipient = prefs.getString(PREF_PUBLIC_MOD, DEFAULT_PREF);
		String pubExpRecipient = prefs.getString(PREF_PUBLIC_EXP, DEFAULT_PREF);
		String privateModRecipient = prefs.getString(PREF_PRIVATE_MOD,
				DEFAULT_PREF);
		String privateExpRecipient = prefs.getString(PREF_PRIVATE_EXP,
				DEFAULT_PREF);

		boolean recipientsKeysExist = false;

		if (!pubModRecipient.equals(DEFAULT_PREF)
				&& !pubExpRecipient.equals(DEFAULT_PREF)
				&& !privateModRecipient.equals(DEFAULT_PREF)
				&& !privateExpRecipient.equals(DEFAULT_PREF)) {
			Log.i(TAG,
					"TESTING - INTENDED RECIPIENT - The intented recipient's keys found, not regenerating");
			recipientsKeysExist = true;
		} else {

			recipientsKeysExist = false;
		}
		if (!recipientsKeysExist) {
			Log.i(TAG,
					"TESTING - INTENDED RECIPIENT - The intented recipient's keys not found, generating now");
			try {

				/*
				 * Generating private and public key using RSA algorithm saving
				 * the keys to the app's shared preferences
				 */
				KeyPairGenerator kpg = KeyPairGenerator.getInstance("RSA");
				kpg.initialize(2048);
				KeyPair kp = kpg.genKeyPair();
				Key publicKey = kp.getPublic();
				Key privateKey = kp.getPrivate();

				KeyFactory fact = KeyFactory.getInstance("RSA");
				RSAPublicKeySpec pub = fact.getKeySpec(publicKey,
						RSAPublicKeySpec.class);
				RSAPrivateKeySpec priv = fact.getKeySpec(privateKey,
						RSAPrivateKeySpec.class);

				/*
				 * save the public key to the app's SharedPreferences and send
				 * it via SMS to the intended recipient
				 */
				// handlePublicKey(pub);
				BigInteger pubModBI = pub.getModulus();
				BigInteger pubExpBI = pub.getPublicExponent();
				Log.i(TAG,
						"TESTING - INTENDED RECIPIENT - the modulus of the current user's public key is "
								+ pubModBI + " and the exponent is " + pubExpBI);
				byte[] pubModBA = pubModBI.toByteArray();// Base64.encodeInteger(pubModBI);
															// // for some
															// strange
															// reason this
															// throws
															// NoSuchMethodError
				byte[] pubExpBA = pubExpBI.toByteArray();// Base64.encodeInteger(pubExpBI);

				try {
					String pubModRecipientBase64Str = Base64.encodeToString(
							pubModBA, Base64.DEFAULT);
					String pubExpRecipientBase64Str = Base64.encodeToString(
							pubExpBA, Base64.DEFAULT);

					// SharedPreferences prefs =
					// getSharedPreferences(PREFS_RECIPIENT,Context.MODE_PRIVATE);
					SharedPreferences.Editor prefsEditor = prefs.edit();

					prefsEditor.putString(PREF_PUBLIC_MOD,
							pubModRecipientBase64Str);
					prefsEditor.putString(PREF_PUBLIC_EXP,
							pubExpRecipientBase64Str);
					// prefsEditor.putString(PREF_PRIVATE_MOD,
					// DEFAULT_PRIVATE_MOD);
					prefsEditor.commit();

					String msg = "keyx " + pubModRecipientBase64Str + " "
							+ pubExpRecipientBase64Str;
					Log.i(TAG,
							"TESTING - INTENDED RECIPIENT - the message after encoded to base64 is: '"
									+ msg + "' and its length is "
									+ msg.length());
					Log.i(TAG,
							"TESTING - INTENDED RECIPIENT - Sending key exchange message to the intended recipient");
					if (msg.length() > 160) {
						sendLongSMS(DEFAULT_RECIPIENT_NUM, msg);
					} else {
						sendSMS(DEFAULT_RECIPIENT_NUM, msg);
					}
				} catch (NoSuchMethodError e) {
					Log.e(TAG, "Base64.encode() method not available", e);
				}

				/*
				 * save the private key to the app's SharedPreferences
				 */
				// savePrivateKey(priv);
				BigInteger privateModBI = priv.getModulus();
				BigInteger privateExpBI = priv.getPrivateExponent();
				Log.i(TAG,
						"TESTING - INTENDED RECIPIENT - the modulus of the current user's private key is "
								+ privateModBI
								+ " and the exponent is "
								+ privateExpBI);
				byte[] privateModBA = privateModBI.toByteArray();// Base64.encodeInteger(pubModBI);
																	// // for
																	// some
																	// strange
																	// reason
																	// this
																	// throws
																	// NoSuchMethodError
				byte[] privateExpBA = privateExpBI.toByteArray();// Base64.encodeInteger(pubExpBI);

				try {
					String recipientPrivateModBase64Str = Base64
							.encodeToString(privateModBA, Base64.DEFAULT);
					String recipientPrivateExpBase64Str = Base64
							.encodeToString(privateExpBA, Base64.DEFAULT);

					// SharedPreferences prefs =
					// getSharedPreferences(PREFS,Context.MODE_PRIVATE);
					SharedPreferences.Editor prefsEditor = prefs.edit();

					prefsEditor.putString(PREF_PRIVATE_MOD,
							recipientPrivateModBase64Str);
					prefsEditor.putString(PREF_PRIVATE_EXP,
							recipientPrivateExpBase64Str);
					// prefsEditor.putString(PREF_PRIVATE_MOD,
					// DEFAULT_PRIVATE_MOD);
					prefsEditor.commit();
				} catch (NoSuchMethodError e) {
					Log.e(TAG, "Base64.encode() method not available", e);
				}

			} catch (NoSuchAlgorithmException e) {
				Log.e(TAG, "RSA algorithm not available", e);
			} catch (InvalidKeySpecException e) {
				Log.e(TAG, "", e);
			}
		} else {
			byte[] recipientPubModBA = Base64.decode(pubModRecipient,
					Base64.DEFAULT);
			byte[] recipientPubExpBA = Base64.decode(pubExpRecipient,
					Base64.DEFAULT);
			byte[] recipientPrivateModBA = Base64.decode(privateModRecipient,
					Base64.DEFAULT);
			byte[] recipientPrivateExpBA = Base64.decode(privateExpRecipient,
					Base64.DEFAULT);

			BigInteger recipientPubMod = new BigInteger(recipientPubModBA);
			BigInteger recipientPubExp = new BigInteger(recipientPubExpBA);
			BigInteger recipientPrivateMod = new BigInteger(
					recipientPrivateModBA);
			BigInteger recipientPrivateExp = new BigInteger(
					recipientPrivateExpBA);

			Log.i(TAG,
					"TESTING - INTENDED RECIPIENT - the current user's stored public key modulus is "
							+ recipientPubMod
							+ " while the exponent is "
							+ recipientPubExp
							+ " === private key modulus is "
							+ recipientPrivateMod
							+ " and exponent is "
							+ recipientPrivateExp);
		}
	}

	public void handlePublicKey(RSAPublicKeySpec publicKey) {
		BigInteger pubModBI = publicKey.getModulus();
		BigInteger pubExpBI = publicKey.getPublicExponent();
		Log.i(TAG, "the modulus of the current user's public key is "
				+ pubModBI + " and the exponent is " + pubExpBI);
		byte[] pubModBA = pubModBI.toByteArray();// Base64.encodeInteger(pubModBI);
													// // for some strange
													// reason this throws
													// NoSuchMethodError
		byte[] pubExpBA = pubExpBI.toByteArray();// Base64.encodeInteger(pubExpBI);

		try {
			String pubModBase64Str = Base64.encodeToString(pubModBA,
					Base64.DEFAULT);
			String pubExpBase64Str = Base64.encodeToString(pubExpBA,
					Base64.DEFAULT);

			savePublicKey(pubModBase64Str, pubExpBase64Str);

			//sendKeyExchangeSMS(pubModBase64Str, pubExpBase64Str);
		} catch (NoSuchMethodError e) {
			Log.e(TAG, "Base64.encode() method not available", e);
		}
	}

	public void savePublicKey(String mod, String exp) {
		SharedPreferences prefs = getSharedPreferences(PREFS,
				Context.MODE_PRIVATE);
		SharedPreferences.Editor prefsEditor = prefs.edit();

		prefsEditor.putString(PREF_PUBLIC_MOD, mod);
		prefsEditor.putString(PREF_PUBLIC_EXP, exp);
		// prefsEditor.putString(PREF_PRIVATE_MOD, DEFAULT_PRIVATE_MOD);
		prefsEditor.commit();
	}

	private void savePublicKey(RSAPublicKeySpec pubKey) {
		BigInteger pubModBI = pubKey.getModulus();
		BigInteger pubExpBI = pubKey.getPublicExponent();

		byte[] pubModBA = pubModBI.toByteArray();// Base64.encodeInteger(pubModBI);
													// // for some strange
													// reason this throws
													// NoSuchMethodError
		byte[] pubExpBA = pubExpBI.toByteArray();// Base64.encodeInteger(pubExpBI);

		try {
			String pubModBase64Str = Base64.encodeToString(pubModBA,
					Base64.DEFAULT);
			String pubExpBase64Str = Base64.encodeToString(pubExpBA,
					Base64.DEFAULT);

			Log.i(TAG, "the modulus of the current user's public key is "
					+ pubModBI + " and the exponent is " + pubExpBI
					+ " | encoded module is " + pubModBase64Str
					+ " | encoded exponent is " + pubExpBase64Str);

			savePublicKey(pubModBase64Str, pubExpBase64Str);

		} catch (NoSuchMethodError e) {
			Log.e(TAG, "Base64.encode() method not available", e);
		}
		// TODO extract the modulus and exponent and save them
	}

	public void sendKeyExchangeSMS(String recipient, String mod, String exp) {
		String msg = "keyx " + mod + " " + exp;
		Log.i(TAG, "Sending key exchange sms: '"+msg+"'");
		TextView debug = (TextView) findViewById(R.id.DebugMessages);
		debug.append("Sending key exchange sms: '"+msg+"'");
		if (msg.length() > 160) {
			sendLongSMS(recipient, msg);
		} else {
			sendSMS(recipient, msg);
		}
	}

	private void sendKeyExchangeSMS() {
		// TODO to retrieve the modulus and exponent of the curent user's public key
		SharedPreferences prefs = getSharedPreferences(PREFS,
				Context.MODE_PRIVATE);
		
		String pubMod = prefs.getString(PREF_PUBLIC_MOD, DEFAULT_PREF);
		String pubExp = prefs.getString(PREF_PUBLIC_EXP, DEFAULT_PREF);
		
		EditText recipient = (EditText) findViewById(R.id.InputRecipientNum);
		sendKeyExchangeSMS(recipient.getText().toString(), pubMod, pubExp);
	}

	public void savePrivateKey(RSAPrivateKeySpec privateKey) {
		BigInteger privateModBI = privateKey.getModulus();
		BigInteger privateExpBI = privateKey.getPrivateExponent();
		
		byte[] privateModBA = privateModBI.toByteArray();// Base64.encodeInteger(pubModBI);
															// // for some
															// strange reason
															// this throws
															// NoSuchMethodError
		byte[] privateExpBA = privateExpBI.toByteArray();// Base64.encodeInteger(pubExpBI);

		try {
			String privateModBase64Str = Base64.encodeToString(privateModBA,
					Base64.DEFAULT);
			String privateExpBase64Str = Base64.encodeToString(privateExpBA,
					Base64.DEFAULT);
			Log.i(TAG, "the modulus of the current user's private key is "
					+ privateModBI + " and the exponent is " + privateExpBI
					+ " | encoded module is " + privateModBase64Str
					+ " | encoded exponent is " + privateExpBase64Str);
			
			savePrivateKey(privateModBase64Str, privateExpBase64Str);

		} catch (NoSuchMethodError e) {
			Log.e(TAG, "Base64.encode() method not available", e);
		}
	}

	private void savePrivateKey(String mod, String exp) {
		SharedPreferences prefs = getSharedPreferences(PREFS,
				Context.MODE_PRIVATE);
		SharedPreferences.Editor prefsEditor = prefs.edit();

		prefsEditor.putString(PREF_PRIVATE_MOD, mod);
		prefsEditor.putString(PREF_PRIVATE_EXP, exp);
		// prefsEditor.putString(PREF_PRIVATE_MOD, DEFAULT_PRIVATE_MOD);
		prefsEditor.commit();
	}

	public void sendEncryptedMessage(String msg) {
		Log.i(TAG,
				"original message is '" + msg + "' with length " + msg.length());
		// reconstruct the public key of the intended recipient providing the
		// modulus and exponent are stored in the app's SharedPreferences

		SharedPreferences prefs = getSharedPreferences(PREFS_RECIPIENT,
				Context.MODE_PRIVATE);

		String pubMod = prefs.getString(PREF_PUBLIC_MOD, DEFAULT_PREF);
		String pubExp = prefs.getString(PREF_PUBLIC_EXP, DEFAULT_PREF);
		String recipient = prefs.getString(PREF_RECIPIENT_NUM,
				DEFAULT_RECIPIENT_NUM);
		if (!pubMod.equals(DEFAULT_PREF) && !pubExp.equals(DEFAULT_PREF)) {
			byte[] curPubModBA = Base64.decode(pubMod, Base64.DEFAULT);
			byte[] curPubExpBA = Base64.decode(pubExp, Base64.DEFAULT);
			BigInteger curPubMod = new BigInteger(curPubModBA);
			BigInteger curPubExp = new BigInteger(curPubExpBA);

			RSAPublicKeySpec recipientPublicKeySpec = new RSAPublicKeySpec(
					curPubMod, curPubExp);
			try {
				KeyFactory fact = KeyFactory.getInstance("RSA");

				PublicKey pubKey = fact.generatePublic(recipientPublicKeySpec);

				// TODO encrypt the message and send it
				Cipher cipher = Cipher.getInstance("RSA");
				cipher.init(Cipher.ENCRYPT_MODE, pubKey);
				byte[] msgByteArray = msg.getBytes();
				byte[] cipherData = cipher.doFinal(msgByteArray);

				String encodedCipherData = Base64.encodeToString(cipherData,
						Base64.DEFAULT);

				// String encryptedMsg = new String(cipherData);
				Log.i(TAG, "encrypted message is : '" + new String(cipherData)
						+ "' and it became " + encodedCipherData
						+ " after Base64 encoding with length "
						+ encodedCipherData.length() + " being sent to "
						+ recipient);
				if (encodedCipherData.length() > 160) {
					sendLongSMS(recipient, encodedCipherData);
				} else {
					sendSMS(recipient, encodedCipherData);
				}

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
		} else {
			Log.i(TAG,
					"can't send the message yet since the intended recipient's public key is not known");
		}
	}

	private void registerReceivers() {
		String SENT = "SMS_SENT";
		String DELIVERED = "SMS_DELIVERED";
		// ---when the SMS has been sent---
		registerReceiver(new BroadcastReceiver() {
			@Override
			public void onReceive(Context arg0, Intent arg1) {
				switch (getResultCode()) {
				case Activity.RESULT_OK:
					Toast.makeText(getBaseContext(), "SMS sent",
							Toast.LENGTH_SHORT).show();
					Log.i(TAG, "SMS sent");
					TextView debug = (TextView) findViewById(R.id.DebugMessages);
					debug.append("SMS sent");
					break;
				case SmsManager.RESULT_ERROR_GENERIC_FAILURE:
					Toast.makeText(getBaseContext(), "Generic failure",
							Toast.LENGTH_SHORT).show();
					Log.w(TAG, "Generic failure");
					break;
				case SmsManager.RESULT_ERROR_NO_SERVICE:
					Toast.makeText(getBaseContext(), "No service",
							Toast.LENGTH_SHORT).show();
					Log.w(TAG, "No service");
					break;
				case SmsManager.RESULT_ERROR_NULL_PDU:
					Toast.makeText(getBaseContext(), "Null PDU",
							Toast.LENGTH_SHORT).show();
					Log.w(TAG, "Null PDU");
					break;
				case SmsManager.RESULT_ERROR_RADIO_OFF:
					Toast.makeText(getBaseContext(), "Radio off",
							Toast.LENGTH_SHORT).show();
					Log.w(TAG, "Radio off");
					break;
				}
			}
		}, new IntentFilter(SENT));

		// ---when the SMS has been delivered---
		registerReceiver(new BroadcastReceiver() {
			@Override
			public void onReceive(Context arg0, Intent arg1) {
				switch (getResultCode()) {
				case Activity.RESULT_OK:
					Toast.makeText(getBaseContext(), "SMS delivered",
							Toast.LENGTH_SHORT).show();
					Log.i(TAG, "SMS delivered");
					TextView debug = (TextView) findViewById(R.id.DebugMessages);
					debug.append("SMS sent");
					break;
				case Activity.RESULT_CANCELED:
					Toast.makeText(getBaseContext(), "SMS not delivered",
							Toast.LENGTH_SHORT).show();
					Log.w(TAG, "SMS not delivered");
					break;
				}
			}
		}, new IntentFilter(DELIVERED));
	}

	private void initialiseOnClickListeners() {

		Button btnGenKeys = (Button) findViewById(R.id.BtnGenerateKeys);
		btnGenKeys.setOnClickListener(new OnClickListener() {
			@Override
			public void onClick(View v) {
				// TODO generate private and public keys and store them
				handleKeys();
				EditText recipient = (EditText) findViewById(R.id.InputRecipientNum);
				EditText message = (EditText) findViewById(R.id.InputSMS);
				InputMethodManager imm = (InputMethodManager)getSystemService(
					      Context.INPUT_METHOD_SERVICE);
					imm.hideSoftInputFromWindow(recipient.getWindowToken(), 0);
					imm.hideSoftInputFromWindow(message.getWindowToken(), 0);
			}
		});

		Button btnShareKey = (Button) findViewById(R.id.BtnShareKey);
		btnShareKey.setOnClickListener(new OnClickListener() {
			@Override
			public void onClick(View v) {
				// TODO share the public key with the intended recipient
				
				sendKeyExchangeSMS();
				EditText recipient = (EditText) findViewById(R.id.InputRecipientNum);
				EditText message = (EditText) findViewById(R.id.InputSMS);
				InputMethodManager imm = (InputMethodManager)getSystemService(
					      Context.INPUT_METHOD_SERVICE);
					imm.hideSoftInputFromWindow(recipient.getWindowToken(), 0);
					imm.hideSoftInputFromWindow(message.getWindowToken(), 0);
			}
		});

		Button btnSendSMS = (Button) findViewById(R.id.BtnSendSMS);
		btnSendSMS.setOnClickListener(new OnClickListener() {
			@Override
			public void onClick(View v) {
				// TODO encrypt the SMS message using the public key of the
				// intended recipient and send it
				EditText recipient = (EditText) findViewById(R.id.InputRecipientNum);
				EditText message = (EditText) findViewById(R.id.InputSMS);
				sendSecureSMS(recipient.getText().toString(), getApplicationContext());
				
				InputMethodManager imm = (InputMethodManager)getSystemService(
					      Context.INPUT_METHOD_SERVICE);
					imm.hideSoftInputFromWindow(message.getWindowToken(), 0);
					imm.hideSoftInputFromWindow(recipient.getWindowToken(), 0);
			}
		});
	}

	private void sendSecureSMS(String recipient, Context context) {
		// TODO retrieve the private key
		RSAPublicKeySpec pubKey = MyKeyUtils.getPublicKeySpec(context);
		// TODO encrypt the main content of the message using the private key
		EditText smsMessage = (EditText) findViewById(R.id.InputSMS);
		String msg = smsMessage.getText().toString();
		String encryptedMsg = Base64.encodeToString(
				MyKeyUtils.encryptMsg(msg, pubKey), Base64.DEFAULT);

		// TODO encode the main content of the message and compose the SMS
		// message
		String smsMsg = HEALTH_SMS + " " + encryptedMsg;
		TextView debug = (TextView) findViewById(R.id.DebugMessages);
		debug.append("Sending secure sms: '"+smsMsg+"'");
		// TODO send the SMS message
		if (smsMsg.length() > 160) {
			Log.i(TAG, "sms is " + smsMsg + " and recipient is " + recipient);
			sendLongSMS(recipient, smsMsg);
		} else {
			Log.i(TAG, "sms is " + smsMsg + " and recipient is " + recipient);
			sendSMS(recipient, smsMsg);
		}
	}

}
