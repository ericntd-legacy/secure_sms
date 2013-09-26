package com.example.simplesms;

import java.math.BigInteger;
import java.util.HashMap;
import java.util.Map;

//import org.apache.commons.codec.binary.Base64;
import android.util.Base64;

import android.content.BroadcastReceiver;
import android.content.Context;
import android.content.Intent;
import android.os.Bundle;
import android.telephony.SmsMessage;
import android.util.Log;

public class SmsReceiver extends BroadcastReceiver {
	// debugging
	private final String TAG = "SmsReceiver";
	
	private final String KEY_EXCHANGE_CODE = "keyx";
	
	@Override
	public void onReceive(Context context, Intent intent) {
		Map<String, String> msg = retrieveMessages(intent);
		
		Log.i(TAG, "we received "+msg.size()+" messages in total");
        if (msg!=null) {
        	for (String sender : msg.keySet()) {
        		String message = msg.get(sender);
        		
        		Log.i(TAG, "message received is "+ message);
        		
        		handleMessage(message, sender);
        	}
        }
		
		
	}
	
	private void handleMessage(String message, String sender) {
		if (message.startsWith(KEY_EXCHANGE_CODE)) {
			Log.i(TAG, "message received is a key exchange message");
			handleKeyExchangeMsg(message, sender);
		} else {
			Log.i(TAG, "received a secure text message");
			// TODO handle secure text message
		}
	}
	
	private void handleKeyExchangeMsg(String message, String sender) {
		// TODO get the modulus and exponent of the public key of the sender & reconstruct the public key
		String[] parts = message.split(" ");
		if (parts.length==3) {
			String senderPubModBase64Str = parts[1];
			String senderPubExpBase64Str = parts[2];
			
			byte[] senderPubModBA = Base64.decodeBase64(senderPubModBase64Str);
			BigInteger senderPubMod = new BigInteger(senderPubModBA);
			
			Log.i(TAG, "the public key module of the sender is "+senderPubMod);
		} else {
			Log.e(TAG, "something is wrong with the key exchange message, it's supposed to have 3 parts: the code 'keyx', the modulus and the exponent");
		}
		
		// TODO store the public key received from the sender
		
		
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
