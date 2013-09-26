package com.example.simplesms;

import java.math.BigInteger;
import java.util.HashMap;
import java.util.Map;

//import org.apache.commons.codec.binary.Base64;
import android.util.Base64;

import android.content.BroadcastReceiver;
import android.content.Context;
import android.content.Intent;
import android.content.SharedPreferences;
import android.os.Bundle;
import android.telephony.SmsMessage;
import android.util.Log;

public class SmsReceiver extends BroadcastReceiver {
	// debugging
	private final String TAG = "SmsReceiver";
	
	// SharedPreferences
	private final String PREFS = "PublicKeyRecipient";
	private final String PREF_PUBLIC_MOD = "PublicModulus";
	private final String PREF_PUBLIC_EXP = "PublicExponent";
	private final String PREF_PHONE_NUMBER = "PhoneNumber";
	
	private final String DEFAULT_PREF = "";
	
	private final String KEY_EXCHANGE_CODE = "keyx";
	
	@Override
	public void onReceive(Context context, Intent intent) {
		Map<String, String> msg = retrieveMessages(intent);
		
		Log.i(TAG, "we received "+msg.size()+" messages in total");
        if (msg!=null) {
        	for (String sender : msg.keySet()) {
        		String message = msg.get(sender);
        		
        		Log.i(TAG, "message received is "+ message);
        		
        		handleMessage(message, sender, context);
        	}
        }
		
		
	}
	
	private void handleMessage(String message, String sender, Context context) {
		if (message.startsWith(KEY_EXCHANGE_CODE)) {
			Log.i(TAG, "message received is a key exchange message");
			handleKeyExchangeMsg(message, sender, context);
		} else {
			Log.i(TAG, "received a secure text message");
			// TODO handle secure text message
		}
	}
	
	/*
	 * the sender here is actually the recipient of future encrypted text messages
	 * the recipient's public key will be used to encrypt the future text messages
	 * so that the recipient can use his/ her private key to decrypt the messages upon receiving them
	 */
	private void handleKeyExchangeMsg(String message, String sender, Context context) {
		// TODO get the modulus and exponent of the public key of the sender & reconstruct the public key
		String recipient = sender;
		String[] parts = message.split(" ");
		if (parts.length==3) {
			String recipientPubModBase64Str = parts[1];
			String recipientPubExpBase64Str = parts[2];
			
			byte[] recipientPubModBA = Base64.decode(recipientPubModBase64Str, Base64.DEFAULT);
			byte[] recipientPubExpBA = Base64.decode(recipientPubExpBase64Str, Base64.DEFAULT);
			BigInteger recipientPubMod = new BigInteger(recipientPubModBA);
			BigInteger recipientPubExp = new BigInteger(recipientPubExpBA);
			
			Log.i(TAG, "the recipient's public key modulus is "+recipientPubMod + " and exponent is "+recipientPubExp);
			
			
			// TODO store the intended recipient's public key in the app's SharedPreferences
			SharedPreferences prefs = context.getSharedPreferences(PREFS,
					Context.MODE_PRIVATE);
			SharedPreferences.Editor prefsEditor = prefs.edit();

			prefsEditor.putString(PREF_PUBLIC_MOD, recipientPubModBase64Str);
			prefsEditor.putString(PREF_PUBLIC_EXP, recipientPubExpBase64Str);
			prefsEditor.putString(PREF_PHONE_NUMBER, recipient);
			prefsEditor.commit();
		} else {
			Log.e(TAG, "something is wrong with the key exchange message, it's supposed to have 3 parts: the code 'keyx', the modulus and the exponent");
		}
		
		
	}
	
	private Map<String, String> retrieveMessages(Intent intent) {
        Map<String, String> msg = null; 
        SmsMessage[] msgs = null;
        Bundle bundle = intent.getExtras();
        
        if (bundle != null && bundle.containsKey("pdus")) {
            Object[] pdus = (Object[]) bundle.get("pdus");

            if (pdus != null) {
                int nbrOfpdus = pdus.length;
                msg = new HashMap<String, String>(nbrOfpdus);
                msgs = new SmsMessage[nbrOfpdus];
                
                // There can be multiple SMS from multiple senders, there can be a maximum of nbrOfpdus different senders
                // However, send long SMS of same sender in one message
                for (int i = 0; i < nbrOfpdus; i++) {
                    msgs[i] = SmsMessage.createFromPdu((byte[])pdus[i]);
                    
                    String originatinAddress = msgs[i].getOriginatingAddress();
                    
                    // Check if index with number exists                    
                    if (!msg.containsKey(originatinAddress)) { 
                        // Index with number doesn't exist                                               
                        // Save string into associative array with sender number as index
                        msg.put(msgs[i].getOriginatingAddress(), msgs[i].getMessageBody()); 
                        
                    } else {    
                        // Number has been there, add content but consider that
                        // msg.get(originatinAddress) already contains sms:sndrNbr:previousparts of SMS, 
                        // so just add the part of the current PDU
                        String previousparts = msg.get(originatinAddress);
                        String msgString = previousparts + msgs[i].getMessageBody();
                        msg.put(originatinAddress, msgString);
                    }
                }
            }
        }
        
        return msg;
    }
}
