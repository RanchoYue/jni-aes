package com.example.aes;

import android.os.Bundle;
import android.util.Log;
import android.widget.Toast;

import androidx.appcompat.app.AppCompatActivity;

public class MainActivity extends AppCompatActivity {

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        setContentView(R.layout.activity_main);
        TestJNI testJNI = new TestJNI();
        findViewById(R.id.btn).setOnClickListener(view -> {
            String s = testJNI.encrypt("qf");
            Log.e("yue_", "encrypt: " + s);
            Toast.makeText(MainActivity.this, s, Toast.LENGTH_SHORT).show();
        });
    }
}