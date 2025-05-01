package com.auditor;

import javax.swing.*;
import java.awt.*;

public class App {

    public static void main(String[] args) {
        SwingUtilities.invokeLater(() -> {
            JFrame frame = new JFrame("Website Auditor");
            frame.setDefaultCloseOperation(JFrame.EXIT_ON_CLOSE);
            frame.setSize(600, 400);
            frame.setLocationRelativeTo(null);

            // Add the main panel from SceneController
            frame.add(new SceneController().getMainPanel());

            frame.setVisible(true);
        });
    }
}
