package com.exef.utils;

import javax.swing.JTextArea;

public final class Logger {

    private static volatile Logger instance = null;

    public static Logger getInstance() {
        if (instance == null) {
            synchronized (Logger.class) {
                if (instance == null) {
                    instance = new Logger();
                }
            }
        }
        return instance;
    }

    private Logger() {
    }
    private static JTextArea output;

    public static void addMessage(String message) {
        if (output == null) {
            System.out.println(message);
        } else {
            output.setText(output.getText() + "\n" + message);
        }
    }

    public void setOutput(JTextArea jTextArea2) {
        output = jTextArea2;
    }
}
