package com.example.simplesms;

import java.io.BufferedOutputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.ObjectOutputStream;
import java.math.BigInteger;
import java.security.Key;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.RSAPrivateKeySpec;
import java.security.spec.RSAPublicKeySpec;
import java.util.ArrayList;

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
import android.util.Log;
import android.view.Menu;
import android.widget.Toast;

public class MainActivity extends Activity {
	// debugging
	private final String TAG = "MainActivity";
	
	// sharedpreference
	private final String PREFS = "MySecureSMS";
	private final String PREF_PUBLIC_MOD = "PublicModulus";
	private final String PREF_PUBLIC_EXP = "PublicExponent";
	private final String PREF_PRIVATE_MOD = "PrivateModulus";
	private final String PREF_PRIVATE_EXP = "PrivateExponent";
	
	private final String DEFAULT_PREF = "";
	
	// intents
	private final String INTENT_SOURCE = "Source";

	@Override
	protected void onCreate(Bundle savedInstanceState) {
		super.onCreate(savedInstanceState);
		setContentView(R.layout.activity_main);
		
		Log.i(TAG, "onCreate");
		
		// TODO process the intent if any
		Intent intent = getIntent();
		if (intent!=null) {
			Log.i(TAG, "activity launched by some intent from "+intent.getStringExtra(INTENT_SOURCE));
		}

		// TODO create the pair of private key & public key based on a
		// passphrase and something random
		try {
			KeyPairGenerator kpg = KeyPairGenerator.getInstance("RSA");
			kpg.initialize(2048);
			KeyPair kp = kpg.genKeyPair();
			Key publicKey = kp.getPublic();
			Key privateKey = kp.getPrivate();

			KeyFactory fact = KeyFactory.getInstance("RSA");
			RSAPublicKeySpec pub = fact.getKeySpec(publicKey, RSAPublicKeySpec.class);
			RSAPrivateKeySpec priv = fact.getKeySpec(privateKey, RSAPrivateKeySpec.class);
			
			//Not sure if it's a better idea to save the keys to text file or sharedpreference
			//saveToFile("public.key", pub.getModulus(), pub.getPublicExponent());
			//saveToFile("private.key", priv.getModulus(), priv.getPrivateExponent());
			saveToPref(PREF_PUBLIC_MOD, pub.getModulus());
			saveToPref(PREF_PUBLIC_EXP, pub.getPublicExponent());
			saveToPref(PREF_PRIVATE_MOD, priv.getModulus());
			saveToPref(PREF_PRIVATE_EXP, priv.getPrivateExponent());
		} catch (NoSuchAlgorithmException e) {
			Log.e(TAG, "RSA algorithm not available", e);
		} catch (InvalidKeySpecException e) {
			Log.e(TAG, "", e);
		} /*catch (IOException e) {
			Log.e(TAG, "Having trouble saving key file", e);
		}*/
		
		// TODO to bind the activity to SendReceiveService
		//doBindService();

		// TODO to send the public key send via sms
		SharedPreferences prefs = getSharedPreferences(PREFS, Context.MODE_PRIVATE);
		//SmsManager smsManager = SmsManager.getDefault();
		
		String phoneNum = "+6593628809";
		String publicModString = prefs.getString(PREF_PUBLIC_MOD, DEFAULT_PREF);
		
		Log.i(TAG, "length of public key modulus is "+publicModString.length());
		if (publicModString.length()>160) sendLongSMS(phoneNum, publicModString);
		else sendSMS(phoneNum, publicModString);
		
		/*String scAddress = null;
		Intent it = new Intent(SendReceiveService.SENT_SMS_ACTION, null, getApplicationContext(), SendReceiveService.class);
		it.putExtra(INTENT_SOURCE, "self");
		PendingIntent sentIntent = PendingIntent.getBroadcast(getApplicationContext(), 0, it, 0);
		PendingIntent deliveredIntent = null;*/
		//Log.i(TAG, "sending public key modulus " + publicModString + " to "+phoneNum);
		//smsManager.sendTextMessage(phoneNum, scAddress, publicModString, sentIntent, deliveredIntent);
		
		//TODO to integrate the encryption to Kong SMS app and send the SMS via such app instead of sending it directly here

		// TODO to encrypt a message using the private key and send via sms &
		// send a digital signature

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
		doUnbindService();
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
		
		Log.i(TAG, "modulus/ exponent length in bytes is "+st.length());
		SharedPreferences prefs = getSharedPreferences(PREFS, Context.MODE_PRIVATE);
		SharedPreferences.Editor prefsEditor = prefs.edit();
		
		prefsEditor.putString(pref, st);
		//prefsEditor.putString(PREF_PRIVATE_MOD, DEFAULT_PRIVATE_MOD);
		prefsEditor.commit();
		
		//Log.i(TAG, prefs.getString(pref, DEFAULT_PREF) + " was successfully stored as "+pref );
	}
	
	private SendReceiveService mBoundService;

	private ServiceConnection mConnection = new ServiceConnection() {
	    public void onServiceConnected(ComponentName className, IBinder service) {
	    	Log.i(TAG, "Activitiy bound to "+className.toString()+" using binder "+service.toString());
	        // This is called when the connection with the service has been
	        // established, giving us the service object we can use to
	        // interact with the service.  Because we have bound to a explicit
	        // service that we know is running in our own process, we can
	        // cast its IBinder to a concrete class and directly access it.
	        mBoundService = ((SendReceiveService.LocalBinder)service).getService();

	        // Tell the user about this for our demo.
	        //Toast.makeText(MainActivity.this, "sendreceiveservice connected", Toast.LENGTH_SHORT).show();
	    }

	    public void onServiceDisconnected(ComponentName className) {
	        // This is called when the connection with the service has been
	        // unexpectedly disconnected -- that is, its process crashed.
	        // Because it is running in our same process, we should never
	        // see this happen.
	        /*mBoundService = null;
	        Toast.makeText(Binding.this, R.string.local_service_disconnected,
	                Toast.LENGTH_SHORT).show();*/
	    }
	};
	
	private boolean mIsBound = false;

	void doBindService() {
		Log.i(TAG, "binding the activity to SendReceiveService");
	    // Establish a connection with the service.  We use an explicit
	    // class name because we want a specific service implementation that
	    // we know will be running in our own process (and thus won't be
	    // supporting component replacement by other applications).
		Intent intent = new Intent(MainActivity.this, SendReceiveService.class);
		intent.putExtra(INTENT_SOURCE, "MainActivity");
	    bindService(intent, mConnection, Context.BIND_AUTO_CREATE);
	    mIsBound = true;
	}

	void doUnbindService() {
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
			sentIntents.add(PendingIntent.getBroadcast(getApplicationContext(), 0, new Intent(SENT), 0));
			deliveryIntents.add(PendingIntent.getBroadcast(getApplicationContext(), 0, new Intent(DELIVERED), 0));
		}

		sm.sendMultipartTextMessage(phoneNum,null, parts, sentIntents, deliveryIntents);
	}
	
	public void sendSMS(String phoneNum, String message) {
		String SENT = "SMS_SENT";
	    String DELIVERED = "SMS_DELIVERED";

	    PendingIntent sentPI = PendingIntent.getBroadcast(this, 0,
	        new Intent(SENT), 0);

	    PendingIntent deliveredPI = PendingIntent.getBroadcast(this, 0,
	        new Intent(DELIVERED), 0);

	    //---when the SMS has been sent---
	    registerReceiver(new BroadcastReceiver(){
	        @Override
	        public void onReceive(Context arg0, Intent arg1) {
	            switch (getResultCode())
	            {
	                case Activity.RESULT_OK:
	                    Toast.makeText(getBaseContext(), "SMS sent", 
	                            Toast.LENGTH_SHORT).show();

	                    break;
	                case SmsManager.RESULT_ERROR_GENERIC_FAILURE:
	                    Toast.makeText(getBaseContext(), "Generic failure", 
	                            Toast.LENGTH_SHORT).show();
	                    break;
	                case SmsManager.RESULT_ERROR_NO_SERVICE:
	                    Toast.makeText(getBaseContext(), "No service", 
	                            Toast.LENGTH_SHORT).show();
	                    break;
	                case SmsManager.RESULT_ERROR_NULL_PDU:
	                    Toast.makeText(getBaseContext(), "Null PDU", 
	                            Toast.LENGTH_SHORT).show();
	                    break;
	                case SmsManager.RESULT_ERROR_RADIO_OFF:
	                    Toast.makeText(getBaseContext(), "Radio off", 
	                            Toast.LENGTH_SHORT).show();
	                    break;
	            }
	        }
	    }, new IntentFilter(SENT));

	    //---when the SMS has been delivered---
	    registerReceiver(new BroadcastReceiver(){
	        @Override
	        public void onReceive(Context arg0, Intent arg1) {
	            switch (getResultCode())
	            {
	                case Activity.RESULT_OK:
	                    Toast.makeText(getBaseContext(), "SMS delivered", 
	                            Toast.LENGTH_SHORT).show();

	                    break;
	                case Activity.RESULT_CANCELED:
	                    Toast.makeText(getBaseContext(), "SMS not delivered", 
	                            Toast.LENGTH_SHORT).show();
	                    break;                        
	            }
	        }
	    }, new IntentFilter(DELIVERED));        

	    SmsManager sms = SmsManager.getDefault();
	    sms.sendTextMessage(phoneNum, null, message, sentPI, deliveredPI);
	}

}
