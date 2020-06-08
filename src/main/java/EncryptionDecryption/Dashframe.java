package EncryptionDecryption;


import java.util.Base64;
import javax.crypto.KeyGenerator;
import javax.crypto.Cipher;
import javax.crypto.SecretKey;

public class Dashframe extends javax.swing.JFrame {
    public Dashframe() {
        initComponents();
    }
    
    private static Cipher cipher = null;
    // <editor-fold defaultstate="collapsed" desc="Generated Code">//GEN-BEGIN:initComponents
    private void initComponents() {

        jPanel1 = new javax.swing.JPanel();
        DecryptedLabel = new javax.swing.JLabel();
        fileEncryptButton = new javax.swing.JButton();
        messageFieldInput = new javax.swing.JTextField();
        DecryptionOutput = new javax.swing.JTextField();
        EncryptionToolLabel = new javax.swing.JLabel();
        EncryptedLabel = new javax.swing.JLabel();
        EncryptionOutput = new javax.swing.JTextField();
        EncryptionButton = new javax.swing.JButton();
        fileDecryptButton = new javax.swing.JButton();

        setDefaultCloseOperation(javax.swing.WindowConstants.EXIT_ON_CLOSE);
        setTitle("Dashboard");
        setBackground(new java.awt.Color(104, 52, 122));
        setCursor(new java.awt.Cursor(java.awt.Cursor.DEFAULT_CURSOR));
        setForeground(java.awt.Color.white);
        setMinimumSize(new java.awt.Dimension(1000, 600));

        jPanel1.setBackground(new java.awt.Color(37, 42, 65));

        DecryptedLabel.setFont(new java.awt.Font("Century Gothic", 1, 22)); // NOI18N
        DecryptedLabel.setForeground(new java.awt.Color(255, 255, 255));
        DecryptedLabel.setHorizontalAlignment(javax.swing.SwingConstants.RIGHT);
        DecryptedLabel.setText("Decrypted Message: ");

        fileEncryptButton.setFont(new java.awt.Font("Century Gothic", 1, 16)); // NOI18N
        fileEncryptButton.setText("Encrypt File");
        fileEncryptButton.setBorderPainted(false);
        fileEncryptButton.addMouseListener(new java.awt.event.MouseAdapter() {
            public void mouseClicked(java.awt.event.MouseEvent evt) {
                fileEncryptButtonMouseClicked(evt);
            }
        });

        messageFieldInput.setFont(new java.awt.Font("Century Gothic", 1, 20)); // NOI18N
        messageFieldInput.setHorizontalAlignment(javax.swing.JTextField.CENTER);
        messageFieldInput.setText("Enter Message");
        messageFieldInput.addActionListener(new java.awt.event.ActionListener() {
            public void actionPerformed(java.awt.event.ActionEvent evt) {
                messageFieldInputActionPerformed(evt);
            }
        });

        DecryptionOutput.setFont(new java.awt.Font("Century Gothic", 1, 20)); // NOI18N
        DecryptionOutput.setHorizontalAlignment(javax.swing.JTextField.CENTER);
        DecryptionOutput.setPreferredSize(new java.awt.Dimension(198, 45));
        DecryptionOutput.addActionListener(new java.awt.event.ActionListener() {
            public void actionPerformed(java.awt.event.ActionEvent evt) {
                DecryptionOutputActionPerformed(evt);
            }
        });

        EncryptionToolLabel.setFont(new java.awt.Font("Century Gothic", 1, 56)); // NOI18N
        EncryptionToolLabel.setForeground(new java.awt.Color(255, 255, 255));
        EncryptionToolLabel.setHorizontalAlignment(javax.swing.SwingConstants.CENTER);
        EncryptionToolLabel.setText("Encryption Tool");

        EncryptedLabel.setFont(new java.awt.Font("Century Gothic", 1, 22)); // NOI18N
        EncryptedLabel.setForeground(new java.awt.Color(255, 255, 255));
        EncryptedLabel.setHorizontalAlignment(javax.swing.SwingConstants.RIGHT);
        EncryptedLabel.setText("Encrypted Message: ");

        EncryptionOutput.setFont(new java.awt.Font("Century Gothic", 1, 20)); // NOI18N
        EncryptionOutput.setHorizontalAlignment(javax.swing.JTextField.CENTER);
        EncryptionOutput.setPreferredSize(new java.awt.Dimension(198, 45));
        EncryptionOutput.addActionListener(new java.awt.event.ActionListener() {
            public void actionPerformed(java.awt.event.ActionEvent evt) {
                EncryptionOutputActionPerformed(evt);
            }
        });

        EncryptionButton.setFont(new java.awt.Font("Century Gothic", 1, 16)); // NOI18N
        EncryptionButton.setText("Encrypt");
        EncryptionButton.setBorderPainted(false);
        EncryptionButton.addMouseListener(new java.awt.event.MouseAdapter() {
            public void mouseClicked(java.awt.event.MouseEvent evt) {
                EncryptionButtonMouseClicked(evt);
            }
        });

        fileDecryptButton.setFont(new java.awt.Font("Century Gothic", 1, 16)); // NOI18N
        fileDecryptButton.setText("Decrypt File");
        fileDecryptButton.setBorderPainted(false);
        fileDecryptButton.addMouseListener(new java.awt.event.MouseAdapter() {
            public void mouseClicked(java.awt.event.MouseEvent evt) {
                fileDecryptButtonMouseClicked(evt);
            }
        });

        javax.swing.GroupLayout jPanel1Layout = new javax.swing.GroupLayout(jPanel1);
        jPanel1.setLayout(jPanel1Layout);
        jPanel1Layout.setHorizontalGroup(
            jPanel1Layout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
            .addGroup(jPanel1Layout.createSequentialGroup()
                .addGroup(jPanel1Layout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
                    .addGroup(jPanel1Layout.createSequentialGroup()
                        .addGap(308, 308, 308)
                        .addComponent(messageFieldInput, javax.swing.GroupLayout.PREFERRED_SIZE, 384, javax.swing.GroupLayout.PREFERRED_SIZE)
                        .addGap(18, 18, 18)
                        .addComponent(EncryptionButton))
                    .addGroup(jPanel1Layout.createSequentialGroup()
                        .addContainerGap()
                        .addComponent(EncryptedLabel, javax.swing.GroupLayout.PREFERRED_SIZE, 310, javax.swing.GroupLayout.PREFERRED_SIZE)
                        .addPreferredGap(javax.swing.LayoutStyle.ComponentPlacement.UNRELATED)
                        .addComponent(EncryptionOutput, javax.swing.GroupLayout.PREFERRED_SIZE, 634, javax.swing.GroupLayout.PREFERRED_SIZE))
                    .addGroup(jPanel1Layout.createSequentialGroup()
                        .addContainerGap()
                        .addComponent(DecryptedLabel, javax.swing.GroupLayout.PREFERRED_SIZE, 310, javax.swing.GroupLayout.PREFERRED_SIZE)
                        .addPreferredGap(javax.swing.LayoutStyle.ComponentPlacement.UNRELATED)
                        .addGroup(jPanel1Layout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
                            .addGroup(jPanel1Layout.createSequentialGroup()
                                .addComponent(fileEncryptButton)
                                .addGap(97, 97, 97)
                                .addComponent(fileDecryptButton))
                            .addComponent(DecryptionOutput, javax.swing.GroupLayout.PREFERRED_SIZE, 634, javax.swing.GroupLayout.PREFERRED_SIZE))))
                .addContainerGap(46, Short.MAX_VALUE))
            .addGroup(jPanel1Layout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
                .addGroup(jPanel1Layout.createSequentialGroup()
                    .addContainerGap()
                    .addComponent(EncryptionToolLabel, javax.swing.GroupLayout.DEFAULT_SIZE, 990, Short.MAX_VALUE)
                    .addContainerGap()))
        );
        jPanel1Layout.setVerticalGroup(
            jPanel1Layout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
            .addGroup(jPanel1Layout.createSequentialGroup()
                .addGap(177, 177, 177)
                .addGroup(jPanel1Layout.createParallelGroup(javax.swing.GroupLayout.Alignment.BASELINE)
                    .addComponent(messageFieldInput, javax.swing.GroupLayout.PREFERRED_SIZE, 56, javax.swing.GroupLayout.PREFERRED_SIZE)
                    .addComponent(EncryptionButton, javax.swing.GroupLayout.PREFERRED_SIZE, 56, javax.swing.GroupLayout.PREFERRED_SIZE))
                .addGap(66, 66, 66)
                .addGroup(jPanel1Layout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
                    .addComponent(EncryptionOutput, javax.swing.GroupLayout.PREFERRED_SIZE, 46, javax.swing.GroupLayout.PREFERRED_SIZE)
                    .addComponent(EncryptedLabel, javax.swing.GroupLayout.PREFERRED_SIZE, 54, javax.swing.GroupLayout.PREFERRED_SIZE))
                .addGap(18, 18, 18)
                .addGroup(jPanel1Layout.createParallelGroup(javax.swing.GroupLayout.Alignment.BASELINE)
                    .addComponent(DecryptedLabel, javax.swing.GroupLayout.PREFERRED_SIZE, 54, javax.swing.GroupLayout.PREFERRED_SIZE)
                    .addComponent(DecryptionOutput, javax.swing.GroupLayout.PREFERRED_SIZE, 46, javax.swing.GroupLayout.PREFERRED_SIZE))
                .addGap(72, 72, 72)
                .addGroup(jPanel1Layout.createParallelGroup(javax.swing.GroupLayout.Alignment.BASELINE)
                    .addComponent(fileEncryptButton, javax.swing.GroupLayout.PREFERRED_SIZE, 56, javax.swing.GroupLayout.PREFERRED_SIZE)
                    .addComponent(fileDecryptButton, javax.swing.GroupLayout.PREFERRED_SIZE, 56, javax.swing.GroupLayout.PREFERRED_SIZE))
                .addContainerGap(90, Short.MAX_VALUE))
            .addGroup(jPanel1Layout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
                .addGroup(jPanel1Layout.createSequentialGroup()
                    .addGap(33, 33, 33)
                    .addComponent(EncryptionToolLabel, javax.swing.GroupLayout.PREFERRED_SIZE, 98, javax.swing.GroupLayout.PREFERRED_SIZE)
                    .addContainerGap(512, Short.MAX_VALUE)))
        );

        javax.swing.GroupLayout layout = new javax.swing.GroupLayout(getContentPane());
        getContentPane().setLayout(layout);
        layout.setHorizontalGroup(
            layout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
            .addGroup(layout.createSequentialGroup()
                .addComponent(jPanel1, javax.swing.GroupLayout.PREFERRED_SIZE, javax.swing.GroupLayout.DEFAULT_SIZE, javax.swing.GroupLayout.PREFERRED_SIZE)
                .addGap(0, 0, Short.MAX_VALUE))
        );
        layout.setVerticalGroup(
            layout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
            .addGroup(javax.swing.GroupLayout.Alignment.TRAILING, layout.createSequentialGroup()
                .addGap(0, 0, Short.MAX_VALUE)
                .addComponent(jPanel1, javax.swing.GroupLayout.PREFERRED_SIZE, javax.swing.GroupLayout.DEFAULT_SIZE, javax.swing.GroupLayout.PREFERRED_SIZE))
        );

        setSize(new java.awt.Dimension(1016, 647));
        setLocationRelativeTo(null);
    }// </editor-fold>//GEN-END:initComponents

    private void fileEncryptButtonMouseClicked(java.awt.event.MouseEvent evt) {//GEN-FIRST:event_fileEncryptButtonMouseClicked
        try {   
            AESFileEncryption.encryptFile();
        } catch (Exception e) {
            e.printStackTrace();
        }
        
    }//GEN-LAST:event_fileEncryptButtonMouseClicked

    private void messageFieldInputActionPerformed(java.awt.event.ActionEvent evt) {//GEN-FIRST:event_messageFieldInputActionPerformed
        // TODO add your handling code here:
    }//GEN-LAST:event_messageFieldInputActionPerformed

    private void DecryptionOutputActionPerformed(java.awt.event.ActionEvent evt) {//GEN-FIRST:event_DecryptionOutputActionPerformed
        // TODO add your handling code here:
    }//GEN-LAST:event_DecryptionOutputActionPerformed

    private void EncryptionOutputActionPerformed(java.awt.event.ActionEvent evt) {//GEN-FIRST:event_EncryptionOutputActionPerformed
        // TODO add your handling code here:
    }//GEN-LAST:event_EncryptionOutputActionPerformed

    private void EncryptionButtonMouseClicked(java.awt.event.MouseEvent evt) {//GEN-FIRST:event_EncryptionButtonMouseClicked
        String messageToBeEncrypted = messageFieldInput.getText();
        try {        
            KeyGenerator keyGenerator = KeyGenerator.getInstance("AES");
            keyGenerator.init(128);
            SecretKey secretKey = keyGenerator.generateKey();
            cipher = Cipher.getInstance("AES");
            //messageToBeEncrypted is an argument of the run() function
            String encryptedText = encrypt(messageToBeEncrypted, secretKey);
            String decryptedText = decrypt(encryptedText, secretKey);
            updateField(encryptedText, decryptedText);
            //DecryptionOutput.setVisible(false);
        } catch(Exception e) {
            e.printStackTrace();
        }
    }//GEN-LAST:event_EncryptionButtonMouseClicked

    private void fileDecryptButtonMouseClicked(java.awt.event.MouseEvent evt) {//GEN-FIRST:event_fileDecryptButtonMouseClicked
        try {   
            AESFileDecryption.decryptFile();
        } catch (Exception e) {
            e.printStackTrace();
        }
    }//GEN-LAST:event_fileDecryptButtonMouseClicked

    //ENCRYPT FUNCTION -----------------------------------------------------------------------
    public static String encrypt(String plainText, SecretKey secretKey) throws Exception {
        byte[] plainTextByte = plainText.getBytes("UTF-8");
        cipher.init(Cipher.ENCRYPT_MODE, secretKey);
        byte[] encryptedByte = cipher.doFinal(plainTextByte);
        Base64.Encoder encoder = Base64.getEncoder();
        String encryptedText = encoder.encodeToString(encryptedByte);
        return encryptedText;
    } 
    
    //DECRYPT FUNCTION
    public static String decrypt(String encryptedText, SecretKey secretKey) throws Exception {
        Base64.Decoder decoder = Base64.getDecoder();
        byte[] encryptedTextByte = decoder.decode(encryptedText);
        cipher.init(Cipher.DECRYPT_MODE, secretKey);
        byte[] decryptedByte = cipher.doFinal(encryptedTextByte);
        String decryptedText = new String(decryptedByte);
        return decryptedText;
	}
    
    public void updateField(String encryptedMessage, String decryptedMessage) {
        EncryptionOutput.setText(encryptedMessage);
        DecryptionOutput.setText(decryptedMessage);
    }
    
    //MAIN FUNCTION ------------------
    public static void main(String args[]) {
        //<editor-fold defaultstate="collapsed" desc=" Look and feel setting code (optional) ">
        /* If Nimbus (introduced in Java SE 6) is not available, stay with the default look and feel.
         * For details see http://download.oracle.com/javase/tutorial/uiswing/lookandfeel/plaf.html 
         */
        try {
            for (javax.swing.UIManager.LookAndFeelInfo info : javax.swing.UIManager.getInstalledLookAndFeels()) {
                if ("Nimbus".equals(info.getName())) {
                    javax.swing.UIManager.setLookAndFeel(info.getClassName());
                    break;
                }
            }
        } catch (ClassNotFoundException ex) {
            java.util.logging.Logger.getLogger(Dashframe.class.getName()).log(java.util.logging.Level.SEVERE, null, ex);
        } catch (InstantiationException ex) {
            java.util.logging.Logger.getLogger(Dashframe.class.getName()).log(java.util.logging.Level.SEVERE, null, ex);
        } catch (IllegalAccessException ex) {
            java.util.logging.Logger.getLogger(Dashframe.class.getName()).log(java.util.logging.Level.SEVERE, null, ex);
        } catch (javax.swing.UnsupportedLookAndFeelException ex) {
            java.util.logging.Logger.getLogger(Dashframe.class.getName()).log(java.util.logging.Level.SEVERE, null, ex);
        }
        //</editor-fold>

        /* Create and display the form */
        java.awt.EventQueue.invokeLater(new Runnable() {
            @Override
                public void run() {
                new Dashframe().setVisible(true); 
            }
        });
    }

    // Variables declaration - do not modify//GEN-BEGIN:variables
    private javax.swing.JLabel DecryptedLabel;
    private javax.swing.JTextField DecryptionOutput;
    private javax.swing.JLabel EncryptedLabel;
    private javax.swing.JButton EncryptionButton;
    private javax.swing.JTextField EncryptionOutput;
    private javax.swing.JLabel EncryptionToolLabel;
    private javax.swing.JButton fileDecryptButton;
    private javax.swing.JButton fileEncryptButton;
    private javax.swing.JPanel jPanel1;
    private javax.swing.JTextField messageFieldInput;
    // End of variables declaration//GEN-END:variables
}