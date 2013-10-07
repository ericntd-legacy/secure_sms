package sg.edu.dukenus.crypto;

import com.example.simplesms.R;

import android.app.Notification;
import android.app.NotificationManager;
import android.app.PendingIntent;
import android.app.Service;
import android.content.Context;
import android.content.Intent;
import android.os.Binder;
import android.os.IBinder;
import android.os.Messenger;
import android.support.v4.app.NotificationCompat;
import android.util.Log;
import android.widget.Toast;

public class SendReceiveService extends Service {
	// debugging
	private final String TAG = "SendReceiveService";
	
	// intent actions
	public static final String SEND_SMS_ACTION = "";
	public static final String SENT_SMS_ACTION = "SentSMSAction";
	public static final String DELIVERED_SMS_ACTION = "org.thoughtcrime.securesms.SendReceiveService.DELIVERED_SMS_ACTION";
	public static final String RECEIVE_SMS_ACTION = "org.thoughtcrime.securesms.SendReceiveService.RECEIVE_SMS_ACTION";

	private static final int SEND_SMS = 0;
	private static final int RECEIVE_SMS = 1;
	
	// intent others
	private final String INTENT_SOURCE = "Source";

	private NotificationManager mNM;

	// Unique Identification Number for the Notification.
	// We use it on Notification start, and to cancel it.
	private int NOTIFICATION = 0;

	@Override
	public void onCreate() {
		Log.i(TAG, "onCreate");
		mNM = (NotificationManager) getSystemService(NOTIFICATION_SERVICE);

		// Display a notification about us starting. We put an icon in the
		// status bar.
		showNotification();
	}

	@Override
	public void onDestroy() {
		Log.i(TAG, "onDestroy");
		// Cancel the persistent notification.
		mNM.cancel(NOTIFICATION);

		// Tell the user we stopped.
		Toast.makeText(this, "service stopped", Toast.LENGTH_SHORT).show();
	}

	@Override
	public IBinder onBind(Intent intent) {
		String intentSource = intent.getStringExtra(INTENT_SOURCE);
		Log.i(TAG, "This intent comes from "+intentSource);
		return mBinder;
	}

	// This is the object that receives interactions from clients. See
	// RemoteService for a more complete example.
	private final IBinder mBinder = new LocalBinder();

	/**
	 * Class for clients to access. Because we know this service always runs in
	 * the same process as its clients, we don't need to deal with IPC.
	 */
	public class LocalBinder extends Binder {
		SendReceiveService getService() {
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
