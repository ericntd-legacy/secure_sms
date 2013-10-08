package sg.edu.dukenus.securesms;


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
import java.security.Provider;
import java.security.PublicKey;
import java.security.Security;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.RSAPrivateKeySpec;
import java.security.spec.RSAPublicKeySpec;
import java.util.ArrayList;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;

import sg.edu.dukenus.securesms.crypto.MyKeyUtils;
import sg.edu.dukenus.securesms.service.SendReceiveService;
import sg.edu.dukenus.securesms.sms.SmsReceiver;
import sg.edu.dukenus.securesms.sms.SmsSender;
import sg.edu.dukenus.securesms.utils.MyUtils;

import com.example.simplesms.R;

import android.os.Bundle;
import android.os.IBinder;
import android.app.Activity;
import android.app.AlertDialog;
import android.app.Dialog;
import android.app.PendingIntent;
import android.content.BroadcastReceiver;
import android.content.ComponentName;
import android.content.Context;
import android.content.DialogInterface;
import android.content.Intent;
import android.content.IntentFilter;
import android.content.ServiceConnection;
import android.content.SharedPreferences;
import android.support.v4.app.DialogFragment;
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
	
	// SMS classes
	private SmsSender smsSender;
	private SmsReceiver smsReceiver;

	// sharedpreferences

	//private final String PREF_RECIPIENT_NUM = "RecipientNum";

	// intents
	private final String INTENT_SOURCE = "Source";

	// others
	//private final String DES_NUM = "93628809";

	//final Context context = this;

	// SMS codes
	private final String KEYX = "keyx";
	private final String HEALTH_SMS = "gmstelehealth";

	@Override
	protected void onCreate(Bundle savedInstanceState) {
		super.onCreate(savedInstanceState);
		setContentView(R.layout.activity_main);

		Log.i(TAG, "onCreate");
		
		/*for (Provider provider : Security.getProviders())
		  {
			Log.d(TAG, "provider: "+provider.getName());
		   for (Provider.Service service : provider.getServices())
		   {
		     Log.d(TAG, "algo " + service.getAlgorithm());
		   }
		}*/

		debugMessages = (TextView) findViewById(R.id.DebugMessages);
		debugMessages.setMovementMethod(new ScrollingMovementMethod());

		// for testing only, clearing the SharedPreferences
		if (RESET) {
			/*Log.w(TAG,
					"TESTING - INTENDED RECIPIENT - Resetting the intended recipient's keys");
			SharedPreferences prefs = getSharedPreferences(PREFS_RECIPIENT,
					Context.MODE_PRIVATE);
			SharedPreferences.Editor prefsEditor = prefs.edit();

			prefsEditor.clear();
			prefsEditor.commit();*/
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
		 * Handle the intended recipient's keys for testing
		 */
		// handleRecipientsKeys();

		// TODO to bind the activity to SendReceiveService
		// doBindService();

		// TODO to send the public key send via sms
		// SharedPreferences prefs = getSharedPreferences(MyKeyUtils.PREFS_MY_KEYS,
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

		//String message = "gmstelehealth @systolic=100@ @diastolic=70@ @hr=70@";
		// sendEncryptedMessage(message);
		
		// TODO Check keys in SharedPreferences for server's number +6584781395
		SharedPreferences prefs = getSharedPreferences(MyKeyUtils.DEFAULT_CONTACT_NUM, Context.MODE_PRIVATE);
		String contactPubMod = prefs.getString(MyKeyUtils.PREF_PUBLIC_MOD, MyKeyUtils.DEFAULT_PREF);
		String contactPubExp = prefs.getString(MyKeyUtils.PREF_PUBLIC_EXP, MyKeyUtils.DEFAULT_PREF);
		if (!contactPubMod.isEmpty()&&!contactPubExp.isEmpty()) {
			Log.i(TAG, "public key stored for "+MyKeyUtils.DEFAULT_CONTACT_NUM+" with mod: "+contactPubMod+" and exp: "+contactPubExp);
		} else {
			Log.w(TAG, "public key not found for "+MyKeyUtils.DEFAULT_CONTACT_NUM+" so where did it go?");
		}
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
		// doUnbindService();
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

	/*public void saveToPref(String pref, BigInteger num) {
		String st = new String(num.toByteArray());

		// Log.i(TAG, "modulus/ exponent length in bytes is " + st.length());
		SharedPreferences prefs = getSharedPreferences(MyKeyUtils.PREFS_MY_KEYS,
				Context.MODE_PRIVATE);
		SharedPreferences.Editor prefsEditor = prefs.edit();

		prefsEditor.putString(pref, st);
		// prefsEditor.putString(PREF_PRIVATE_MOD, DEFAULT_PRIVATE_MOD);
		prefsEditor.commit();

		// Log.i(TAG, prefs.getString(pref, MyKeyUtils.DEFAULT_PREF) +
		// " was successfully stored as "+pref );
	}*/

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
	

	/*public void handlePublicKey(RSAPublicKeySpec publicKey) {
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

			// sendKeyExchangeSMS(pubModBase64Str, pubExpBase64Str);
		} catch (NoSuchMethodError e) {
			Log.e(TAG, "Base64.encode() method not available", e);
		}
	}*/

	/*public void sendEncryptedMessage(String msg) {
		Log.i(TAG,
				"original message is '" + msg + "' with length " + msg.length());
		// reconstruct the public key of the intended recipient providing the
		// modulus and exponent are stored in the app's SharedPreferences

		SharedPreferences prefs = getSharedPreferences(PREFS_RECIPIENT,
				Context.MODE_PRIVATE);

		String pubMod = prefs.getString(MyKeyUtils.PREF_PUBLIC_MOD, MyKeyUtils.DEFAULT_PREF);
		String pubExp = prefs.getString(MyKeyUtils.PREF_PUBLIC_EXP, MyKeyUtils.DEFAULT_PREF);
		String recipient = prefs.getString(PREF_RECIPIENT_NUM,
				DEFAULT_RECIPIENT_NUM);
		if (!pubMod.equals(MyKeyUtils.DEFAULT_PREF) && !pubExp.equals(MyKeyUtils.DEFAULT_PREF)) {
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
	}*/

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
				
				/*EditText keySizeField = (EditText) findViewById();
				int keySize = Integer.valueOf(keySizeField.getText().toString());*/
				int keySize = 1024;
				//MyKeyUtils.checkKeys(keySize, getApplicationContext());
				// for now, we don't check, just re-generate anyway
				MyKeyUtils.generateKeys(keySize, getApplicationContext());
				
				EditText recipient = (EditText) findViewById(R.id.InputRecipientNum);
				EditText message = (EditText) findViewById(R.id.InputSMS);
				InputMethodManager imm = (InputMethodManager) getSystemService(Context.INPUT_METHOD_SERVICE);
				imm.hideSoftInputFromWindow(recipient.getWindowToken(), 0);
				imm.hideSoftInputFromWindow(message.getWindowToken(), 0);
			}
		});

		Button btnShareKey = (Button) findViewById(R.id.BtnShareKey);
		btnShareKey.setOnClickListener(new OnClickListener() {
			@Override
			public void onClick(View v) {
				// TODO share the public key with the intended recipient
				EditText recipient = (EditText) findViewById(R.id.InputRecipientNum);
				EditText message = (EditText) findViewById(R.id.InputSMS);
				String recipientNum = recipient.getText().toString();// TODO
																		// must
																		// process
																		// the
																		// number
																		// to
																		// take
																		// care
																		// of
																		// country
																		// code
				if (recipientNum.length() == 0) {
					// TODO prompt user to enter a phone number
					Log.w(TAG, "phone number not entered");

					MyUtils.alert("phone number not entered", MainActivity.this);

				} else {
					smsSender = new SmsSender(recipientNum);
					smsSender.sendKeyExchangeSMS(getApplicationContext());

					InputMethodManager imm = (InputMethodManager) getSystemService(Context.INPUT_METHOD_SERVICE);
					imm.hideSoftInputFromWindow(recipient.getWindowToken(), 0);
					imm.hideSoftInputFromWindow(message.getWindowToken(), 0);
				}
			}
		});

		Button btnSendSMS = (Button) findViewById(R.id.BtnSendSMS);
		btnSendSMS.setOnClickListener(new OnClickListener() {
			@Override
			public void onClick(View v) {
				// TODO encrypt the SMS message using the public key of the
				// intended recipient and send it
				EditText measurementField = (EditText) findViewById(R.id.InputSMS);
				EditText recipient = (EditText) findViewById(R.id.InputRecipientNum);
				String recipientNum = recipient.getText().toString();// TODO
																		// must
																		// process
																		// the
																		// number
																		// to
																		// take
																		// care
																		// of
																		// country
																		// code
				String measurementStr = measurementField.getText().toString();
				if (recipientNum.length() == 0) {
					// TODO prompt user to enter a phone number
					Log.w(TAG, "phone number not entered");

					MyUtils.alert("Please enter a phone number", MainActivity.this);

				} else if (measurementStr.length() == 0) {
					Log.w(TAG, "sms message not entered");

					MyUtils.alert("Please enter a message", MainActivity.this);
				} else {
					smsSender = new SmsSender(recipientNum);
					smsSender.sendSecureSMS(getApplicationContext(), measurementStr);

					InputMethodManager imm = (InputMethodManager) getSystemService(Context.INPUT_METHOD_SERVICE);
					imm.hideSoftInputFromWindow(measurementField.getWindowToken(), 0);
					imm.hideSoftInputFromWindow(recipient.getWindowToken(), 0);
				}
			}
		});
	}

}
