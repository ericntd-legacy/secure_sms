package sg.edu.dukenus.securesms.service;

import android.app.Service;
import android.content.Intent;
import android.os.IBinder;

public class MyKeyService extends Service {

	@Override
	public IBinder onBind(Intent arg0) {
		// TODO Auto-generated method stub
		return null;
	}
	
	@Override
	public int onStartCommand(Intent intent, int flags, int startId) {
		return 0;
	}

}
