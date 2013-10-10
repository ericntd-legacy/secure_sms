package sg.edu.dukenus.securesms.service;

import sg.edu.dukenus.securesms.MainActivity;
import sg.edu.dukenus.securesms.crypto.MyKeyUtils;
import sg.edu.dukenus.securesms.sms.SmsReceiver;
import sg.edu.dukenus.securesms.sms.SmsSender;

import com.example.simplesms.R;

import android.app.IntentService;
import android.app.Notification;
import android.app.NotificationManager;
import android.app.PendingIntent;
import android.app.Service;
import android.content.Context;
import android.content.Intent;
import android.content.IntentFilter;
import android.content.SharedPreferences;
import android.os.Binder;
import android.os.IBinder;
import android.os.Messenger;
import android.support.v4.app.NotificationCompat;
import android.util.Log;
import android.widget.Toast;

public class SendReceiveService extends Service {
	// debugging
	private final String TAG = "SendReceiveService";
	
	// This is the object that receives interactions from clients. See
		// RemoteService for a more complete example.
	private final IBinder mBinder = new LocalBinder();
	private int mStartMode;
	
	// intent actions
	public static final String SEND_SMS_ACTION = "";
	public static final String SENT_SMS_ACTION = "SentSMSAction";
	public static final String DELIVERED_SMS_ACTION = "org.thoughtcrime.securesms.SendReceiveService.DELIVERED_SMS_ACTION";
	public static final String RECEIVE_SMS_ACTION = "org.thoughtcrime.securesms.SendReceiveService.RECEIVE_SMS_ACTION";

	private static final int SEND_SMS = 0;
	private static final int RECEIVE_SMS = 1;
	
	// intent others
	private final String INTENT_SOURCE = "Source";
	
	//private SmsReceiver smsReceiver;
	//private static final String ACTION="android.provider.Telephony.SMS_RECEIVED";
	private SmsSender smsSender;

	private NotificationManager mNM;

	// Unique Identification Number for the Notification.
	// We use it on Notification start, and to cancel it.
	private int NOTIFICATION = 0;
	
	

	@Override
	public void onCreate() {
		//super.onCreate();
		Log.w(TAG, "onCreate");
		mNM = (NotificationManager) getSystemService(NOTIFICATION_SERVICE);

		// Display a notification about us starting. We put an icon in the
		// status bar.
		showNotification();
		
		// TODO register the broadcastlistener to listen for incoming SMSs
		//final IntentFilter theFilter = new IntentFilter();
        //theFilter.addAction(ACTION);
        //this.registerReceiver(this.smsReceiver, theFilter);
		//smsReceiver = new SmsReceiver();
		
		// TODO check keys
		SharedPreferences prefs = getSharedPreferences(MainActivity.DEFAULT_SERVER_NUM, Context.MODE_PRIVATE);
		String contactPubMod = prefs.getString(MyKeyUtils.PREF_PUBLIC_MOD, MyKeyUtils.DEFAULT_PREF);
		String contactPubExp = prefs.getString(MyKeyUtils.PREF_PUBLIC_EXP, MyKeyUtils.DEFAULT_PREF);
		if (!contactPubMod.isEmpty()&&!contactPubExp.isEmpty()) {
			Log.i(TAG, "public key stored for "+MainActivity.DEFAULT_SERVER_NUM+" with mod: "+contactPubMod+" and exp: "+contactPubExp);
		} else {
			Log.w(TAG, "public key not found for "+MainActivity.DEFAULT_SERVER_NUM+", sending a request for it");
			
			// TODO check if own key pair exists, if yes, send a key exchange message to server in order to get key exchange message back
			// if own key pair does not exit, generate one and then request for key from server
			// should probably do this in a separate thread?
			//MyKeyUtils.requestForKey(MainActivity.DEFAULT_SERVER_NUM, getApplicationContext());
		}
		
		mStartMode = 1;
	}
	
	@Override
	public int onStartCommand(Intent intent, int flags, int startId) {
		Log.w(TAG, "onStartCommand");
		return mStartMode;
	}

	@Override
	public void onDestroy() {
		Log.w(TAG, "onDestroy");
		// Cancel the persistent notification.
		mNM.cancel(NOTIFICATION);

		// Tell the user we stopped.
		Toast.makeText(this, "service stopped", Toast.LENGTH_SHORT).show();
		//super.onDestroy();
	}

	@Override
	public IBinder onBind(Intent intent) {
		String intentSource = intent.getStringExtra(INTENT_SOURCE);
		Log.w(TAG, "This intent comes from "+intentSource);
		
		return mBinder;
	}

	/**
	 * Class for clients to access. Because we know this service always runs in
	 * the same process as its clients, we don't need to deal with IPC.
	 */
	public class LocalBinder extends Binder {
		public SendReceiveService getService() {
			return SendReceiveService.this;
		}
	}

	/**
	 * Show a notification while this service is running.
	 */
	private void showNotification() {
		// In this sample, we'll use the same text for the ticker and the
		// expanded notification
		String text = "SendReceiveService";

		// Set the icon, scrolling text and timestamp
		//Notification notification = new Notification(0, text, System.currentTimeMillis());
		
		
		NotificationCompat.Builder mBuilder =
	            new NotificationCompat.Builder(this)
				.setSmallIcon(R.drawable.noti_icon_1)
	            .setContentTitle("SendReceiveService")
	            .setContentText("SendReceiveService is running");
		mNM.notify(NOTIFICATION, mBuilder.build());

		// The PendingIntent to launch our activity if the user selects this
		// notification
		/*PendingIntent contentIntent = PendingIntent.getActivity(this, 0,
				new Intent(this, MainActivity.class), 0);*/

		// Set the info for the views that show in the notification panel.
		//notification.setLatestEventInfo(this, "notification panel view", text, contentIntent);
	}
}
