using System;
using System.Drawing;
using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Crypto.IO;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Security;
using System.Security.Cryptography;
using System.Windows.Forms;
using System.Diagnostics;
using System.Text;
using System.IO;

namespace File_Encrypter
{
    public partial class Form1 : Form
    {
        private Panel container;
        private Panel leftHalf;
        private ComboBox comboBox;
        private TextBox textBox;
        private System.Windows.Forms.Label lhlabel;
        private System.Windows.Forms.Label selectedFilesLabel;
        System.Windows.Forms.Label infoLabel;
        private string[] selectedFiles;
        protected static byte[] serpent_key = new byte[16];
        protected static byte[] twofish_key = new byte[16];
        protected static byte[] aes_key = new byte[16];
        protected static byte[] encryption_key = new byte[16];
        protected static byte[] verification_key = new byte[16];
        protected static byte[] decrypted_tag = new byte[32];

        public Form1()
        {
            InitializeComponent();
            InitializeGUI();
            lhlabel.Click += (sender, e) =>
            {
                open_file_selection_dialog();
            };
            CenterContainer();
            this.Resize += (sender, e) => CenterContainer();
        }

        private static byte[] CalculateHMACSHA256(byte[] data)
        {
            using (HMACSHA256 hmac = new HMACSHA256(verification_key))
            {
                return hmac.ComputeHash(data);
            }
        }

        public static byte[] StringToByteArray(string hex)
        {
            int length = hex.Length;
            byte[] byteArray = new byte[length / 2];

            for (int i = 0; i < length; i += 2)
            {
                byteArray[i / 2] = Convert.ToByte(hex.Substring(i, 2), 16);
            }

            return byteArray;
        }

        private static byte[] GenerateRandomByteArray(int length)
        {
            byte[] randomBytes = new byte[length];

            using (RandomNumberGenerator rng = RandomNumberGenerator.Create())
            {
                rng.GetBytes(randomBytes);
            }

            return randomBytes;
        }

        private byte[] GetSHA512Hash(byte[] input, int iterations)
        {
            using (var sha512 = SHA512.Create())
            {
                for (int i = 0; i < iterations; i++)
                {
                    input = sha512.ComputeHash(input);
                }
                return input;
            }
        }

        private byte[] GetSHA256Hash(byte[] input, int iterations)
        {
            using (var sha256 = SHA256.Create())
            {
                for (int i = 0; i < iterations; i++)
                {
                    input = sha256.ComputeHash(input);
                }
                return input;
            }
        }

        public static int CalculateElmntSum(byte[] input)
        {
            int sum = 0;
            foreach (byte b in input)
            {
                sum += b;
            }
            return sum;
        }

        private static byte[] CombineByteArrays(params byte[][] arrays)
        {
            byte[] rv = new byte[arrays.Sum(a => a.Length)];
            int offset = 0;
            foreach (byte[] array in arrays)
            {
                Buffer.BlockCopy(array, 0, rv, offset, array.Length);
                offset += array.Length;
            }
            return rv;
        }

        private void InitializeGUI()
        {
            this.BackColor = ColorTranslator.FromHtml("#10A95B");

            container = new Panel();
            container.Size = new Size(640, 198);
            container.BackColor = ColorTranslator.FromHtml("#2C2C2C");
            container.BorderStyle = BorderStyle.None;
            container.Region = Region.FromHrgn(CreateRoundRectRgn(0, 0, container.Width, container.Height, 14, 14));
            this.Controls.Add(container);

            leftHalf = new Panel();
            leftHalf.Size = new Size(container.Width / 2, container.Height);
            leftHalf.BackColor = ColorTranslator.FromHtml("#EEEEEE");
            leftHalf.AllowDrop = true;
            leftHalf.DragEnter += new DragEventHandler(LeftHalf_DragEnter);
            leftHalf.DragDrop += new DragEventHandler(LeftHalf_DragDrop);
            container.Controls.Add(leftHalf);

            lhlabel = new System.Windows.Forms.Label();
            lhlabel.Text = "Drag && Drop Files Here\n\nor\n\nClick to Select Files";
            lhlabel.Font = new Font("Segoe UI Semibold", 10, FontStyle.Regular);
            lhlabel.ForeColor = ColorTranslator.FromHtml("#2c2c2c");
            lhlabel.Dock = DockStyle.Fill; // This will make the label fill the entire space of the panel
            lhlabel.TextAlign = ContentAlignment.MiddleCenter; // This will center the text horizontally and vertically
            leftHalf.Controls.Add(lhlabel);

            Panel rightHalf = new Panel();
            rightHalf.Size = new Size(container.Width / 2, container.Height);
            rightHalf.Location = new Point(container.Width / 2, 0);
            rightHalf.BackColor = ColorTranslator.FromHtml("#FFFFFF");
            container.Controls.Add(rightHalf);

            TableLayoutPanel maintableLayout = new TableLayoutPanel();

            maintableLayout.Dock = DockStyle.Fill;
            maintableLayout.ColumnCount = 1;
            maintableLayout.RowCount = 5;

            selectedFilesLabel = new System.Windows.Forms.Label();
            selectedFilesLabel.Text = "Selected Files: 0";
            selectedFilesLabel.Font = new Font("Segoe UI Semibold", 10, FontStyle.Regular);
            selectedFilesLabel.TextAlign = ContentAlignment.MiddleCenter;
            selectedFilesLabel.Size = new Size(rightHalf.Width, selectedFilesLabel.PreferredHeight);
            maintableLayout.Controls.Add(new System.Windows.Forms.Label(), 0, 0);
            maintableLayout.Controls.Add(selectedFilesLabel, 0, 1);

            TableLayoutPanel tableLayout = new TableLayoutPanel();
            tableLayout.Dock = DockStyle.Fill;
            tableLayout.ColumnCount = 3;
            tableLayout.RowCount = 5;

            tableLayout.ColumnStyles.Add(new ColumnStyle(SizeType.Percent, 21));
            tableLayout.ColumnStyles.Add(new ColumnStyle(SizeType.Percent, 58));
            tableLayout.ColumnStyles.Add(new ColumnStyle(SizeType.Percent, 21));
            maintableLayout.Controls.Add(new System.Windows.Forms.Label(), 0, 2);
            maintableLayout.Controls.Add(tableLayout, 0, 3);

            System.Windows.Forms.Label label = new System.Windows.Forms.Label();
            label.Text = "Cipher: ";
            label.Font = new Font("Segoe UI Semibold", 10, FontStyle.Regular);
            label.ForeColor = ColorTranslator.FromHtml("#2c2c2c");
            label.TextAlign = ContentAlignment.MiddleRight;
            tableLayout.Controls.Add(label, 0, 0);

            System.Windows.Forms.Label label2 = new System.Windows.Forms.Label();
            label2.Text = "Key: ";
            label2.Font = new Font("Segoe UI Semibold", 10, FontStyle.Regular);
            label2.ForeColor = ColorTranslator.FromHtml("#2c2c2c");
            label2.TextAlign = ContentAlignment.MiddleRight;
            tableLayout.Controls.Add(label2, 0, 1);

            comboBox = new ComboBox();
            comboBox.Dock = DockStyle.Fill;
            comboBox.Font = new Font("Segoe UI Semibold", 10, FontStyle.Regular);
            comboBox.ForeColor = ColorTranslator.FromHtml("#2c2c2c");
            comboBox.Items.Add("Serpent + Twofish + AES");
            comboBox.Items.Add("AES");
            comboBox.Items.Add("Serpent");
            comboBox.Items.Add("Twofish");
            comboBox.SelectedIndex = 0;

            tableLayout.Controls.Add(comboBox, 1, 0);

            textBox = new TextBox();
            textBox.Dock = DockStyle.Fill;
            textBox.PasswordChar = '*';
            textBox.Font = new Font("Segoe UI Semibold", 10, FontStyle.Regular);
            textBox.ForeColor = ColorTranslator.FromHtml("#2c2c2c");
            tableLayout.Controls.Add(textBox, 1, 1);

            TableLayoutPanel bttnslayout = new TableLayoutPanel();
            bttnslayout.Dock = DockStyle.Fill;
            bttnslayout.ColumnCount = 4;
            bttnslayout.RowCount = 1;
            bttnslayout.Dock = DockStyle.Fill;

            bttnslayout.ColumnStyles.Add(new ColumnStyle(SizeType.Percent, 40));
            bttnslayout.ColumnStyles.Add(new ColumnStyle(SizeType.Percent, 5));
            bttnslayout.ColumnStyles.Add(new ColumnStyle(SizeType.Percent, 40));
            bttnslayout.ColumnStyles.Add(new ColumnStyle(SizeType.Percent, 15));

            Button button1 = new Button();
            button1.Text = "Encrypt";
            button1.Font = new Font("Segoe UI Semibold", 10, FontStyle.Regular);
            button1.BackColor = ColorTranslator.FromHtml("#2D2D2D");
            button1.ForeColor = ColorTranslator.FromHtml("#10A95B");
            button1.FlatStyle = FlatStyle.Flat;
            button1.Cursor = Cursors.Hand;
            button1.Margin = new Padding(0, 0, 0, 0);
            button1.Size = new Size(100, 32);
            button1.Click += (sender, e) => encrypt_files();

            Button button2 = new Button();
            button2.Text = "Decrypt";
            button2.Font = new Font("Segoe UI Semibold", 10, FontStyle.Regular);
            button2.BackColor = ColorTranslator.FromHtml("#2D2D2D");
            button2.ForeColor = ColorTranslator.FromHtml("#10A95B");
            button2.FlatStyle = FlatStyle.Flat;
            button2.Cursor = Cursors.Hand;
            button2.Margin = new Padding(0, 0, 0, 0);
            button2.Size = new Size(100, 32);
            button2.Click += (sender, e) => decrypt_files();

            bttnslayout.Controls.Add(button1, 0, 0);
            bttnslayout.Controls.Add(button2, 2, 0);

            tableLayout.Controls.Add(bttnslayout, 1, 3);
            rightHalf.Controls.Add(maintableLayout);

        }
        [System.Runtime.InteropServices.DllImport("Gdi32.dll", EntryPoint = "CreateRoundRectRgn")]
        private static extern IntPtr CreateRoundRectRgn(int nLeftRect, int nTopRect, int nRightRect, int nBottomRect, int nWidthEllipse, int nHeightEllipse);

        private void CenterContainer()
        {
            container.Location = new Point((this.ClientSize.Width - container.Width) / 2, 99);
        }

        private void open_file_selection_dialog()
        {
            using (OpenFileDialog openFileDialog = new OpenFileDialog())
            {
                openFileDialog.Multiselect = true;
                openFileDialog.Filter = "All Files|*.*|Encrypted Files|*.encr"; // Set the filters
                if (openFileDialog.ShowDialog() == DialogResult.OK)
                {
                    selectedFiles = openFileDialog.FileNames;
                    selectedFilesLabel.Text = "Selected Files: " + selectedFiles.Length;
                }
            }
        }

        private void LeftHalf_DragEnter(object sender, DragEventArgs e)
        {
            if (e.Data.GetDataPresent(DataFormats.FileDrop))
                e.Effect = DragDropEffects.Copy;
            else
                e.Effect = DragDropEffects.None;
        }

        private void LeftHalf_DragDrop(object sender, DragEventArgs e)
        {
            selectedFiles = (string[])e.Data.GetData(DataFormats.FileDrop);
            selectedFilesLabel.Text = "Selected Files: " + selectedFiles.Length;
        }

        public void ShowErrorMessageBox(string line1, string line2)
        {
            Form customMessageBox = new Form
            {
                Text = "File Encrypter Error",
                Size = new Size(640, 162),
                StartPosition = FormStartPosition.CenterScreen,
                BackColor = Color.FromArgb(171, 49, 18)
            };

            // Create label for the first line
            Label label1 = new Label
            {
                Text = line1,
                ForeColor = Color.FromArgb(238, 238, 238),
                Font = new Font("Arial", 16, FontStyle.Bold),
                AutoSize = true,
                TextAlign = ContentAlignment.MiddleCenter
            };
            customMessageBox.Controls.Add(label1);

            // Create label for the second line
            Label label2 = new Label
            {
                Text = line2,
                ForeColor = Color.FromArgb(238, 238, 238),
                Font = new Font("Arial", 14),
                AutoSize = true,
                TextAlign = ContentAlignment.MiddleCenter
            };
            customMessageBox.Controls.Add(label2);

            // Create OK button
            Button okButton = new Button
            {
                Text = "OK",
                Size = new Size(60, 30),
                BackColor = Color.FromArgb(32, 32, 32), // "#202020"
                ForeColor = Color.FromArgb(238, 238, 238), // "#EEEEEE"
                DialogResult = DialogResult.OK,
                FlatStyle = FlatStyle.Flat,
                FlatAppearance = { BorderSize = 0 }
            };
            customMessageBox.Controls.Add(okButton);

            label1.Location = new Point((customMessageBox.ClientSize.Width) / 2, +10);
            label2.Location = new Point((customMessageBox.ClientSize.Width) / 2, label1.Bottom + 10);
            okButton.Location = new Point((customMessageBox.ClientSize.Width - okButton.Width) / 2, label2.Bottom + 12);

            CenterLabelText(label1, customMessageBox);
            CenterLabelText(label2, customMessageBox);

            // Handle Resize event to adjust positions dynamically
            customMessageBox.Resize += (sender, e) =>
            {
                CenterLabelText(label1, customMessageBox);
                CenterLabelText(label2, customMessageBox);
                okButton.Location = new Point((customMessageBox.ClientSize.Width - okButton.Width) / 2, label2.Bottom + 20);
            };

            // Show the message box
            customMessageBox.ShowDialog();
        }

        private void ShowMessageBox(string line1)
        {
            Form customMessageBox = new Form
            {
                Text = "File Encrypter Message",
                Size = new Size(540, 132),
                StartPosition = FormStartPosition.CenterScreen,
                BackColor = ColorTranslator.FromHtml("#D31457")
            };

            Label label1 = new Label
            {
                Text = line1,
                ForeColor = Color.FromArgb(238, 238, 238),
                Font = new Font("Segoe UI Semibold", 12, FontStyle.Regular),
                AutoSize = true,
                TextAlign = ContentAlignment.MiddleCenter
            };
            customMessageBox.Controls.Add(label1);

            Button okButton = new Button
            {
                Text = "OK",
                Size = new Size(70, 30), // Fixed button width
                Font = new Font("Segoe UI Semibold", 10, FontStyle.Regular),
                BackColor = Color.FromArgb(32, 32, 32),
                ForeColor = Color.FromArgb(238, 238, 238),
                DialogResult = DialogResult.Yes,
                FlatStyle = FlatStyle.Flat
            };
            customMessageBox.Controls.Add(okButton);

            label1.Location = new Point((customMessageBox.ClientSize.Width - label1.Width) / 2, 10);

            int buttonY = label1.Bottom + 14;
            int buttonX = (customMessageBox.ClientSize.Width - okButton.Width) / 2;
            okButton.Location = new Point(buttonX, buttonY);

            customMessageBox.Resize += (sender, e) =>
            {
                label1.Location = new Point((customMessageBox.ClientSize.Width - label1.Width) / 2, 10);
                buttonX = (customMessageBox.ClientSize.Width - okButton.Width) / 2;
                okButton.Location = new Point(buttonX, buttonY);
            };

            DialogResult result = customMessageBox.ShowDialog();
        }

        private void CenterLabelText(System.Windows.Forms.Label label,
        Form form)
        {
            label.Location =
            new Point((form.ClientSize.Width - label.Width) / 2,
            label.Location.Y);
        }

        public DialogResult ShowConfirmationMessageBox(string line1)
        {
            Form customMessageBox = new Form
            {
                Text = "File Encrypter Message",
                Size = new Size(640, 162),
                StartPosition = FormStartPosition.CenterScreen,
                BackColor = ColorTranslator.FromHtml("#166899")
            };

            // Create label for the first line
            Label label1 = new Label
            {
                Text = line1,
                ForeColor = Color.FromArgb(238, 238, 238),
                Font = new Font("Segoe UI", 12, FontStyle.Bold),
                AutoSize = true,
                TextAlign = ContentAlignment.MiddleCenter
            };
            customMessageBox.Controls.Add(label1);

            // Create label for the second line
            Label label2 = new Label
            {
                Text = "Would you like to continue?",
                ForeColor = Color.FromArgb(238, 238, 238),
                Font = new Font("Segoe UI", 12),
                AutoSize = true,
                TextAlign = ContentAlignment.MiddleCenter
            };
            customMessageBox.Controls.Add(label2);

            // Create Yes button
            Button yesButton = new Button
            {
                Text = "Yes",
                Size = new Size(60, 30),
                BackColor = Color.FromArgb(32, 32, 32), // "#202020"
                ForeColor = Color.FromArgb(238, 238, 238), // "#EEEEEE"
                DialogResult = DialogResult.Yes,
                FlatStyle = FlatStyle.Flat,
                FlatAppearance = { BorderSize = 0 }
            };
            customMessageBox.Controls.Add(yesButton);

            // Create No button
            Button noButton = new Button
            {
                Text = "No",
                Size = new Size(60, 30),
                BackColor = Color.FromArgb(32, 32, 32), // "#202020"
                ForeColor = Color.FromArgb(238, 238, 238), // "#EEEEEE"
                DialogResult = DialogResult.No,
                FlatStyle = FlatStyle.Flat,
                FlatAppearance = { BorderSize = 0 }
            };
            customMessageBox.Controls.Add(noButton);

            label1.Location = new Point((customMessageBox.ClientSize.Width) / 2, +10);
            label2.Location = new Point((customMessageBox.ClientSize.Width) / 2, label1.Bottom + 10);

            int buttonMargin = 30;
            int buttonWidth = (customMessageBox.ClientSize.Width - 3 * buttonMargin) / 2;

            yesButton.Size = new Size(buttonWidth, 30);
            noButton.Size = new Size(buttonWidth, 30);

            yesButton.Location = new Point(buttonMargin, label2.Bottom + 20);
            noButton.Location = new Point(yesButton.Right + buttonMargin, label2.Bottom + 20);

            CenterLabelText(label1, customMessageBox);
            CenterLabelText(label2, customMessageBox);

            // Handle Resize event to adjust positions dynamically
            customMessageBox.Resize += (sender, e) =>
            {
                CenterLabelText(label1, customMessageBox);
                CenterLabelText(label2, customMessageBox);

                buttonWidth = (customMessageBox.ClientSize.Width - 3 * buttonMargin) / 2;
                yesButton.Size = new Size(buttonWidth, 30);
                noButton.Size = new Size(buttonWidth, 30);

                yesButton.Location = new Point(buttonMargin, label2.Bottom + 20);
                noButton.Location = new Point(yesButton.Right + buttonMargin, label2.Bottom + 20);
            };

            // Show the message box
            DialogResult result = customMessageBox.ShowDialog();

            return result;
        }

        private bool proceed_with_the_process()
        {
            Boolean proceed = true;
            try
            {
                if (selectedFiles == null || selectedFiles.Length == 0)
                {
                    proceed = false;
                    ShowMessageBox("Select at least one file to continue.");
                }

                else if (string.IsNullOrEmpty(textBox.Text))
                {
                    proceed = false;
                    ShowMessageBox("Enter the key to continue.");
                }
            }
            catch (NullReferenceException)
            {
                proceed = false;
                ShowMessageBox("Make sure that you've selected at least one file and entered the key.");
            }

            return proceed;
        }

        private void encrypt_files()
        {
            if (proceed_with_the_process() == true)
            {
                if (comboBox.SelectedIndex == 0)
                {
                    string encr_m;
                    if (selectedFiles.Length == 1)
                        encr_m = "You are about to encrypt a file with Twofish + Serpent + AES in CBC mode.";
                    else
                        encr_m = "You are about to encrypt " + selectedFiles.Length + " files with Twofish + Serpent + AES in CBC mode.";
                    DialogResult result = ShowConfirmationMessageBox(encr_m);

                    if (result == DialogResult.Yes)
                    {
                        set_key_for_tld_encr_alg();

                        foreach (string file in selectedFiles)
                        {
                            EncryptFileWithSerpentTwofishAESCBC(file);
                        }
                        ShowMessageBox("Encryption Done!");
                    }
                    else if (result == DialogResult.No)
                    {
                        ShowMessageBox("Operation Was Cancelled By User.");
                    }
                    else
                    {
                        ShowMessageBox("Operation Was Cancelled By User.");
                    }
                }

                if (comboBox.SelectedIndex == 1)
                {
                    string encr_m;
                    if (selectedFiles.Length == 1)
                        encr_m = "You are about to encrypt a file with AES-256 in CBC mode.";
                    else
                        encr_m = "You are about to encrypt " + selectedFiles.Length + " files with AES-256 in CBC mode.";
                    DialogResult result = ShowConfirmationMessageBox(encr_m);

                    if (result == DialogResult.Yes)
                    {
                        set_key_for_single_encr_alg();

                        foreach (string file in selectedFiles)
                        {
                            EncryptFileWithAES256CBC(file);
                        }
                        ShowMessageBox("Encryption Done!");
                    }
                    else if (result == DialogResult.No)
                    {
                        ShowMessageBox("Operation Was Cancelled By User.");
                    }
                    else
                    {
                        ShowMessageBox("Operation Was Cancelled By User.");
                    }
                }

                if (comboBox.SelectedIndex == 2)
                {
                    string encr_m;
                    if (selectedFiles.Length == 1)
                        encr_m = "You are about to encrypt a file with Serpent in CBC mode.";
                    else
                        encr_m = "You are about to encrypt " + selectedFiles.Length + " files with Serpent in CBC mode.";
                    DialogResult result = ShowConfirmationMessageBox(encr_m);

                    if (result == DialogResult.Yes)
                    {
                        set_key_for_single_encr_alg();

                        foreach (string file in selectedFiles)
                        {
                            EncryptFileWithSerpentCBC(file);
                        }
                        ShowMessageBox("Encryption Done!");
                    }
                    else if (result == DialogResult.No)
                    {
                        ShowMessageBox("Operation Was Cancelled By User.");
                    }
                    else
                    {
                        ShowMessageBox("Operation Was Cancelled By User.");
                    }
                }

                if (comboBox.SelectedIndex == 3)
                {
                    string encr_m;
                    if (selectedFiles.Length == 1)
                        encr_m = "You are about to encrypt a file with Twofish in CBC mode.";
                    else
                        encr_m = "You are about to encrypt " + selectedFiles.Length + " files with Twofish in CBC mode.";
                    DialogResult result = ShowConfirmationMessageBox(encr_m);

                    if (result == DialogResult.Yes)
                    {
                        set_key_for_single_encr_alg();

                        foreach (string file in selectedFiles)
                        {
                            EncryptFileWithTwofishCBC(file);
                        }
                        ShowMessageBox("Encryption Done!");
                    }
                    else if (result == DialogResult.No)
                    {
                        ShowMessageBox("Operation Was Cancelled By User.");
                    }
                    else
                    {
                        ShowMessageBox("Operation Was Cancelled By User.");
                    }
                }
            }
        }

        private void decrypt_files()
        {
            if (proceed_with_the_process() == true)
            {
                if (comboBox.SelectedIndex == 0)
                {
                    string decr_m;
                    if (selectedFiles.Length == 1)
                        decr_m = "You are about to decrypt a file with Twofish + Serpent + AES in CBC mode";
                    else
                        decr_m = "You are about to decrypt " + selectedFiles.Length + " files with Twofish + Serpent + AES in CBC mode.";
                    DialogResult result = ShowConfirmationMessageBox(decr_m);

                    if (result == DialogResult.Yes)
                    {
                        set_key_for_tld_encr_alg();

                        foreach (string file in selectedFiles)
                        {
                            DecryptFileWithAESTwofishSerpentCBC(file);
                        }
                        ShowMessageBox("Decryption Done!");
                    }
                    else if (result == DialogResult.No)
                    {
                        ShowMessageBox("Operation Was Cancelled By User.");
                    }
                    else
                    {
                        ShowMessageBox("Operation Was Cancelled By User.");
                    }
                }

                if (comboBox.SelectedIndex == 1)
                {
                    string decr_m;
                    if (selectedFiles.Length == 1)
                        decr_m = "You are about to decrypt a file with AES-256 in CBC mode.";
                    else
                        decr_m = "You are about to decrypt " + selectedFiles.Length + " files with AES-256 in CBC mode.";
                    DialogResult result = ShowConfirmationMessageBox(decr_m);

                    if (result == DialogResult.Yes)
                    {
                        set_key_for_single_encr_alg();

                        foreach (string file in selectedFiles)
                        {
                            DecryptFileWithAES256CBC(file);
                        }
                        ShowMessageBox("Decryption Done!");
                    }
                    else if (result == DialogResult.No)
                    {
                        ShowMessageBox("Operation Was Cancelled By User.");
                    }
                    else
                    {
                        ShowMessageBox("Operation Was Cancelled By User.");
                    }
                }

                if (comboBox.SelectedIndex == 2)
                {
                    string decr_m;
                    if (selectedFiles.Length == 1)
                        decr_m = "You are about to decrypt a file with Serpent in CBC mode.";
                    else
                        decr_m = "You are about to decrypt " + selectedFiles.Length + " files with Serpent in CBC mode.";
                    DialogResult result = ShowConfirmationMessageBox(decr_m);

                    if (result == DialogResult.Yes)
                    {
                        set_key_for_single_encr_alg();

                        foreach (string file in selectedFiles)
                        {
                            DecryptFileWithSerpentCBC(file);
                        }
                        ShowMessageBox("Decryption Done!");
                    }
                    else if (result == DialogResult.No)
                    {
                        ShowMessageBox("Operation Was Cancelled By User.");
                    }
                    else
                    {
                        ShowMessageBox("Operation Was Cancelled By User.");
                    }
                }

                if (comboBox.SelectedIndex == 3)
                {
                    string decr_m;
                    if (selectedFiles.Length == 1)
                        decr_m = "You are about to decrypt a file with Twofish in CBC mode.";
                    else
                        decr_m = "You are about to decrypt " + selectedFiles.Length + " files with Twofish in CBC mode.";
                    DialogResult result = ShowConfirmationMessageBox(decr_m);

                    if (result == DialogResult.Yes)
                    {
                        set_key_for_single_encr_alg();

                        foreach (string file in selectedFiles)
                        {
                            DecryptFileWithTwofishCBC(file);
                        }
                        ShowMessageBox("Decryption Done!");
                    }
                    else if (result == DialogResult.No)
                    {
                        ShowMessageBox("Operation Was Cancelled By User.");
                    }
                    else
                    {
                        ShowMessageBox("Operation Was Cancelled By User.");
                    }
                }
            }
        }

        private void set_key_for_single_encr_alg()
        {
            byte[] inputBytes = Encoding.UTF8.GetBytes(textBox.Text);
            int num_of_incr = 27 * CalculateElmntSum(GetSHA256Hash(inputBytes, 39 * CalculateElmntSum(inputBytes)));
            byte[] hash = GetSHA512Hash(inputBytes, num_of_incr);

            byte[] resultArray = new byte[32];
            for (int i = 0; i < 32; i++)
            {

                resultArray[i] = (byte)(hash[i] ^ hash[i + 32]);
            }

            for (int i = 0; i < 16; i++)
            {
                encryption_key[i] = resultArray[i];
                verification_key[i] = resultArray[i + 16];
            }
        }

        private void set_key_for_tld_encr_alg()
        {
            byte[] inputBytes = Encoding.UTF8.GetBytes(textBox.Text);
            int num_of_incr = 91 * CalculateElmntSum(GetSHA256Hash(inputBytes, 19 * CalculateElmntSum(inputBytes)));
            byte[] hash = GetSHA512Hash(inputBytes, num_of_incr);

            for (int i = 0; i < 16; i++)
            {
                serpent_key[i] = hash[i];
                twofish_key[i] = hash[i + 16];
                aes_key[i] = hash[i + 32];
                verification_key[i] = hash[i + 48];
            }
        }

        private void EncryptFileWithAES256CBC(string filePath)
        {
            byte[] fileContent = File.ReadAllBytes(filePath);
            byte[] encryptedContent = EncryptWithAESInCBC(fileContent);
            File.WriteAllBytes(filePath + ".encr", encryptedContent);
        }

        public static byte[] EncryptWithAESInCBC(byte[] input)
        {
            byte[] iv = GenerateRandomByteArray(16);
            IBufferedCipher cipher = CipherUtilities.GetCipher("AES/CBC/PKCS7Padding");
            cipher.Init(true, new ParametersWithIV(ParameterUtilities.CreateKeyParameter("AES", encryption_key), iv));

            using (MemoryStream memoryStream = new MemoryStream())
            {
                using (CipherStream cipherStream = new CipherStream(memoryStream, null, cipher))
                {
                    cipherStream.Write(input, 0, input.Length);
                }

                byte[] encryptedHash = StringToByteArray(Encrypt_hash_with_aes_in_cbc(CalculateHMACSHA256(input)));
                byte[] encryptedIV = EncryptAES(iv);
                byte[] encryptedContent = memoryStream.ToArray();

                return CombineByteArrays(encryptedHash, encryptedIV, encryptedContent);
            }
        }

        private static string Encrypt_hash_with_aes_in_cbc(byte[] input)
        {
            byte[] iv = GenerateRandomByteArray(16);
            IBufferedCipher cipher = CipherUtilities.GetCipher("AES/CBC/NoPadding");
            cipher.Init(true, new ParametersWithIV(ParameterUtilities.CreateKeyParameter("AES", encryption_key), iv));

            using (MemoryStream memoryStream = new MemoryStream())
            {
                using (CipherStream cipherStream = new CipherStream(memoryStream, null, cipher))
                {
                    cipherStream.Write(input, 0, input.Length);
                }

                return BitConverter.ToString(EncryptAES(iv)).Replace("-", "") + BitConverter.ToString(memoryStream.ToArray()).Replace("-", "");
            }
        }

        private static byte[] EncryptAES(byte[] data)
        {
            // Create the AES cipher with ECB mode and no padding
            IBufferedCipher cipher = CipherUtilities.GetCipher("AES/ECB/NoPadding");
            cipher.Init(true, new KeyParameter(encryption_key));

            // Encrypt the data
            return cipher.DoFinal(data);
        }

        private void DecryptFileWithAES256CBC(string filePath)
        {
            string new_fp = filePath;
            if (new_fp.EndsWith(".encr"))
            {
                new_fp = new_fp.Substring(0, new_fp.Length - 5);
            }

            DecryptStringWithAESInCBC(File.ReadAllBytes(filePath), new_fp);
        }

        private void DecryptStringWithAESInCBC(byte[] data, string filePath)
        {
            try
            {
                byte[] tag = DecryptHashWithAESInCBC(data.Take(48).ToArray());
                byte[] iv = DecryptAES(data.Skip(48).Take(16).ToArray());
                byte[] encryptedContent = data.Skip(64).ToArray();

                using (MemoryStream memoryStream = new MemoryStream())
                {
                    IBufferedCipher cipher = CipherUtilities.GetCipher("AES/CBC/PKCS7Padding");
                    cipher.Init(false, new ParametersWithIV(ParameterUtilities.CreateKeyParameter("AES", encryption_key), iv));

                    using (CipherStream cipherStream = new CipherStream(memoryStream, null, cipher))
                    {
                        cipherStream.Write(encryptedContent, 0, encryptedContent.Length);
                    }

                    if (!CalculateHMACSHA256(memoryStream.ToArray()).AsSpan().SequenceEqual(tag))
                    {
                        ShowErrorMessageBox("Failed to Verify Integrity/Authenticity of a \"" + Path.GetFileName(filePath) + "\" File", "Decrypted and Computed Tags Don't Match");
                    }
                    else
                    {
                        File.WriteAllBytes(filePath, memoryStream.ToArray());
                    }
                }
            }
            catch (Exception ex)
            {
                ShowErrorMessageBox("Failed to decrypt \"" + Path.GetFileName(filePath) + "\" file.", "Error: " + ex.Message);
            }
        }

        private static byte[] DecryptHashWithAESInCBC(byte[] data)
        {
            byte[] encryptedIV = data.Take(16).ToArray();
            byte[] iv = DecryptAES(encryptedIV);
            byte[] input = data.Skip(16).ToArray();

            IBufferedCipher cipher = CipherUtilities.GetCipher("AES/CBC/NoPadding");
            cipher.Init(false, new ParametersWithIV(ParameterUtilities.CreateKeyParameter("AES", encryption_key), iv));

            using (MemoryStream memoryStream = new MemoryStream())
            {
                using (CipherStream cipherStream = new CipherStream(memoryStream, null, cipher))
                {
                    cipherStream.Write(input, 0, input.Length);
                }

                return memoryStream.ToArray();
            }
        }

        private static byte[] DecryptAES(byte[] encryptedData)
        {
            // Create the AES cipher with ECB mode and no padding
            IBufferedCipher cipher = CipherUtilities.GetCipher("AES/ECB/NoPadding");
            cipher.Init(false, new KeyParameter(encryption_key));

            // Decrypt the data
            return cipher.DoFinal(encryptedData);
        }


        private void EncryptFileWithSerpentCBC(string filePath)
        {
            byte[] fileContent = File.ReadAllBytes(filePath);
            byte[] encryptedContent = EncryptWithSerpentInCBC(fileContent);
            File.WriteAllBytes(filePath + ".encr", encryptedContent);
        }

        public static byte[] EncryptWithSerpentInCBC(byte[] input)
        {
            byte[] iv = GenerateRandomByteArray(16);
            IBufferedCipher cipher = CipherUtilities.GetCipher("Serpent/CBC/PKCS7Padding");
            cipher.Init(true, new ParametersWithIV(ParameterUtilities.CreateKeyParameter("Serpent", encryption_key), iv));

            using (MemoryStream memoryStream = new MemoryStream())
            {
                using (CipherStream cipherStream = new CipherStream(memoryStream, null, cipher))
                {
                    cipherStream.Write(input, 0, input.Length);
                }

                byte[] encryptedHash = EncryptHashWithSerpentInCBC(CalculateHMACSHA256(input));
                byte[] encryptedIV = EncryptSerpent(iv);
                byte[] encryptedContent = memoryStream.ToArray();

                return CombineByteArrays(encryptedHash, encryptedIV, encryptedContent);
            }
        }

        private static byte[] EncryptHashWithSerpentInCBC(byte[] input)
        {
            byte[] iv = GenerateRandomByteArray(16);
            IBufferedCipher cipher = CipherUtilities.GetCipher("Serpent/CBC/NoPadding");
            cipher.Init(true, new ParametersWithIV(ParameterUtilities.CreateKeyParameter("Serpent", encryption_key), iv));

            using (MemoryStream memoryStream = new MemoryStream())
            {
                using (CipherStream cipherStream = new CipherStream(memoryStream, null, cipher))
                {
                    cipherStream.Write(input, 0, input.Length);
                }

                return EncryptSerpent(iv).Concat(memoryStream.ToArray()).ToArray();
            }
        }

        private static byte[] EncryptSerpent(byte[] data)
        {
            // Create the Serpent cipher with ECB mode and no padding
            IBufferedCipher cipher = CipherUtilities.GetCipher("Serpent/ECB/NoPadding");
            cipher.Init(true, new KeyParameter(encryption_key));

            // Encrypt the data
            return cipher.DoFinal(data);
        }

        private void DecryptFileWithSerpentCBC(string filePath)
        {
            string new_fp = filePath;
            if (new_fp.EndsWith(".encr"))
            {
                new_fp = new_fp.Substring(0, new_fp.Length - 5);
            }

            DecryptStringWithSerpentInCBC(File.ReadAllBytes(filePath), new_fp);
        }

        private void DecryptStringWithSerpentInCBC(byte[] data, string filePath)
        {
            try
            {
                byte[] tag = DecryptHashWithSerpentInCBC(data.Take(48).ToArray());
                byte[] iv = DecryptSerpent(data.Skip(48).Take(16).ToArray());
                byte[] encryptedContent = data.Skip(64).ToArray();

                using (MemoryStream memoryStream = new MemoryStream())
                {
                    IBufferedCipher cipher = CipherUtilities.GetCipher("Serpent/CBC/PKCS7Padding");
                    cipher.Init(false, new ParametersWithIV(ParameterUtilities.CreateKeyParameter("Serpent", encryption_key), iv));

                    using (CipherStream cipherStream = new CipherStream(memoryStream, null, cipher))
                    {
                        cipherStream.Write(encryptedContent, 0, encryptedContent.Length);
                    }

                    if (!CalculateHMACSHA256(memoryStream.ToArray()).AsSpan().SequenceEqual(tag))
                    {
                        ShowErrorMessageBox("Failed to Verify Integrity/Authenticity of a \"" + Path.GetFileName(filePath) + "\" File", "Decrypted and Computed Tags Don't Match");
                    }
                    else
                    {
                        File.WriteAllBytes(filePath, memoryStream.ToArray());
                    }
                }
            }
            catch (Exception ex)
            {
                ShowErrorMessageBox("Failed to decrypt \"" + Path.GetFileName(filePath) + "\" file.", "Error: " + ex.Message);
            }
        }

        private static byte[] DecryptHashWithSerpentInCBC(byte[] data)
        {
            byte[] encryptedIV = data.Take(16).ToArray();
            byte[] iv = DecryptSerpent(encryptedIV);
            byte[] input = data.Skip(16).ToArray();

            IBufferedCipher cipher = CipherUtilities.GetCipher("Serpent/CBC/NoPadding");
            cipher.Init(false, new ParametersWithIV(ParameterUtilities.CreateKeyParameter("Serpent", encryption_key), iv));

            using (MemoryStream memoryStream = new MemoryStream())
            {
                using (CipherStream cipherStream = new CipherStream(memoryStream, null, cipher))
                {
                    cipherStream.Write(input, 0, input.Length);
                }

                return memoryStream.ToArray();
            }
        }

        private static byte[] DecryptSerpent(byte[] encryptedData)
        {
            // Create the Serpent cipher with ECB mode and no padding
            IBufferedCipher cipher = CipherUtilities.GetCipher("Serpent/ECB/NoPadding");
            cipher.Init(false, new KeyParameter(encryption_key));

            // Decrypt the data
            return cipher.DoFinal(encryptedData);
        }

        private void DecryptFileWithTwofishCBC(string filePath)
        {
            string new_fp = filePath;
            if (new_fp.EndsWith(".encr"))
            {
                new_fp = new_fp.Substring(0, new_fp.Length - 5);
            }

            DecryptStringWithTwofishInCBC(File.ReadAllBytes(filePath), new_fp);
        }

        private void EncryptFileWithTwofishCBC(string filePath)
        {
            byte[] fileContent = File.ReadAllBytes(filePath);
            byte[] encryptedContent = EncryptWithTwofishInCBC(fileContent);
            File.WriteAllBytes(filePath + ".encr", encryptedContent);
        }

        public static byte[] EncryptWithTwofishInCBC(byte[] input)
        {
            byte[] iv = GenerateRandomByteArray(16);
            IBufferedCipher cipher = CipherUtilities.GetCipher("Twofish/CBC/PKCS7Padding");
            cipher.Init(true, new ParametersWithIV(ParameterUtilities.CreateKeyParameter("Twofish", encryption_key), iv));

            using (MemoryStream memoryStream = new MemoryStream())
            {
                using (CipherStream cipherStream = new CipherStream(memoryStream, null, cipher))
                {
                    cipherStream.Write(input, 0, input.Length);
                }

                byte[] encryptedHash = EncryptHashWithTwofishInCBC(CalculateHMACSHA256(input));
                byte[] encryptedIV = EncryptTwofish(iv);
                byte[] encryptedContent = memoryStream.ToArray();

                return CombineByteArrays(encryptedHash, encryptedIV, encryptedContent);
            }
        }

        private static byte[] EncryptHashWithTwofishInCBC(byte[] input)
        {
            byte[] iv = GenerateRandomByteArray(16);
            IBufferedCipher cipher = CipherUtilities.GetCipher("Twofish/CBC/NoPadding");
            cipher.Init(true, new ParametersWithIV(ParameterUtilities.CreateKeyParameter("Twofish", encryption_key), iv));

            using (MemoryStream memoryStream = new MemoryStream())
            {
                using (CipherStream cipherStream = new CipherStream(memoryStream, null, cipher))
                {
                    cipherStream.Write(input, 0, input.Length);
                }

                return EncryptTwofish(iv).Concat(memoryStream.ToArray()).ToArray();
            }
        }

        private static byte[] EncryptTwofish(byte[] data)
        {
            // Create the Twofish cipher with ECB mode and no padding
            IBufferedCipher cipher = CipherUtilities.GetCipher("Twofish/ECB/NoPadding");
            cipher.Init(true, new KeyParameter(encryption_key));

            // Encrypt the data
            return cipher.DoFinal(data);
        }

        private void DecryptStringWithTwofishInCBC(byte[] data, string filePath)
        {
            try
            {
                byte[] tag = DecryptHashWithTwofishInCBC(data.Take(48).ToArray());
                byte[] iv = DecryptTwofish(data.Skip(48).Take(16).ToArray());
                byte[] encryptedContent = data.Skip(64).ToArray();

                using (MemoryStream memoryStream = new MemoryStream())
                {
                    IBufferedCipher cipher = CipherUtilities.GetCipher("Twofish/CBC/PKCS7Padding");
                    cipher.Init(false, new ParametersWithIV(ParameterUtilities.CreateKeyParameter("Twofish", encryption_key), iv));

                    using (CipherStream cipherStream = new CipherStream(memoryStream, null, cipher))
                    {
                        cipherStream.Write(encryptedContent, 0, encryptedContent.Length);
                    }

                    if (!CalculateHMACSHA256(memoryStream.ToArray()).AsSpan().SequenceEqual(tag))
                    {
                        ShowErrorMessageBox("Failed to Verify Integrity/Authenticity of a \"" + Path.GetFileName(filePath) + "\" File", "Decrypted and Computed Tags Don't Match");
                    }
                    else
                    {
                        File.WriteAllBytes(filePath, memoryStream.ToArray());
                    }
                }
            }
            catch (Exception ex)
            {
                ShowErrorMessageBox("Failed to decrypt \"" + Path.GetFileName(filePath) + "\" file.", "Error: " + ex.Message);
            }
        }

        private static byte[] DecryptHashWithTwofishInCBC(byte[] data)
        {
            byte[] encryptedIV = data.Take(16).ToArray();
            byte[] iv = DecryptTwofish(encryptedIV);
            byte[] input = data.Skip(16).ToArray();

            IBufferedCipher cipher = CipherUtilities.GetCipher("Twofish/CBC/NoPadding");
            cipher.Init(false, new ParametersWithIV(ParameterUtilities.CreateKeyParameter("Twofish", encryption_key), iv));

            using (MemoryStream memoryStream = new MemoryStream())
            {
                using (CipherStream cipherStream = new CipherStream(memoryStream, null, cipher))
                {
                    cipherStream.Write(input, 0, input.Length);
                }

                return memoryStream.ToArray();
            }
        }

        private static byte[] DecryptTwofish(byte[] encryptedData)
        {
            // Create the Twofish cipher with ECB mode and no padding
            IBufferedCipher cipher = CipherUtilities.GetCipher("Twofish/ECB/NoPadding");
            cipher.Init(false, new KeyParameter(encryption_key));

            // Decrypt the data
            return cipher.DoFinal(encryptedData);
        }


        private void EncryptFileWithSerpentTwofishAESCBC(string filePath)
        {
            byte[] fileContent = File.ReadAllBytes(filePath);
            byte[] encryptedContent = EncryptWithSerpentInCBC(fileContent);
            byte[] encryptedContent1 = EncryptWithTwofishInCBC(encryptedContent);
            byte[] encryptedContent2 = EncryptWithAESInCBC(encryptedContent1);
            File.WriteAllBytes(filePath + ".encr", encryptedContent2);
        }


        private void DecryptFileWithAESTwofishSerpentCBC(string filePath)
        {
            string new_fp = filePath;
            if (new_fp.EndsWith(".encr"))
            {
                new_fp = new_fp.Substring(0, new_fp.Length - 5);
            }

            byte[] decrypted_with_aes = DecryptDataWithAESInCBC(File.ReadAllBytes(filePath), new_fp);
            byte[] decrypted_with_twofish = DecryptDataWithTwofishInCBC(decrypted_with_aes, new_fp);
            DecryptStringWithSerpentInCBC(decrypted_with_twofish, new_fp);

        }

        private byte[] DecryptDataWithAESInCBC(byte[] data, string filePath)
        {
            try
            {
                byte[] tag = DecryptHashWithAESInCBC(data.Take(48).ToArray());
                byte[] iv = DecryptAES(data.Skip(48).Take(16).ToArray());
                byte[] encryptedContent = data.Skip(64).ToArray();

                using (MemoryStream memoryStream = new MemoryStream())
                {
                    IBufferedCipher cipher = CipherUtilities.GetCipher("AES/CBC/PKCS7Padding");
                    cipher.Init(false, new ParametersWithIV(ParameterUtilities.CreateKeyParameter("AES", encryption_key), iv));

                    using (CipherStream cipherStream = new CipherStream(memoryStream, null, cipher))
                    {
                        cipherStream.Write(encryptedContent, 0, encryptedContent.Length);
                    }

                    if (!CalculateHMACSHA256(memoryStream.ToArray()).AsSpan().SequenceEqual(tag))
                    {
                        ShowErrorMessageBox("Failed to Verify Integrity/Authenticity of a \"" + Path.GetFileName(filePath) + "\" File", "Decrypted and Computed Tags Don't Match");
                        return new byte[1];
                    }
                    else
                    {
                        return memoryStream.ToArray();
                    }
                }
            }
            catch (Exception ex)
            {
                ShowErrorMessageBox("Failed to decrypt \"" + Path.GetFileName(filePath) + "\" file.", "Error: " + ex.Message);
                return new byte[1];
            }
        }

        private byte[] DecryptDataWithTwofishInCBC(byte[] data, string filePath)
        {
            try
            {
                byte[] tag = DecryptHashWithTwofishInCBC(data.Take(48).ToArray());
                byte[] iv = DecryptTwofish(data.Skip(48).Take(16).ToArray());
                byte[] encryptedContent = data.Skip(64).ToArray();

                using (MemoryStream memoryStream = new MemoryStream())
                {
                    IBufferedCipher cipher = CipherUtilities.GetCipher("Twofish/CBC/PKCS7Padding");
                    cipher.Init(false, new ParametersWithIV(ParameterUtilities.CreateKeyParameter("Twofish", encryption_key), iv));

                    using (CipherStream cipherStream = new CipherStream(memoryStream, null, cipher))
                    {
                        cipherStream.Write(encryptedContent, 0, encryptedContent.Length);
                    }

                    if (!CalculateHMACSHA256(memoryStream.ToArray()).AsSpan().SequenceEqual(tag))
                    {
                        ShowErrorMessageBox("Failed to Verify Integrity/Authenticity of a \"" + Path.GetFileName(filePath) + "\" File", "Decrypted and Computed Tags Don't Match");
                        return new byte[1];
                    }
                    else
                    {
                        return memoryStream.ToArray();
                    }
                }
            }
            catch (Exception ex)
            {
                ShowErrorMessageBox("Failed to decrypt \"" + Path.GetFileName(filePath) + "\" file.", "Error: " + ex.Message);
                return new byte[1];
            }
        }

        private void selectFilesToolStripMenuItem_Click(object sender, EventArgs e)
        {
            open_file_selection_dialog();
        }

        private void listSelectedFilesToolStripMenuItem_Click(object sender, EventArgs e)
        {

            if (selectedFiles == null || selectedFiles.Length == 0)
            {
                ShowMessageBox("Select at least one file to continue.");
            }
            else
            {
                ViewAllFiles selectRecordForm = new ViewAllFiles(selectedFiles);
                DialogResult result = selectRecordForm.ShowDialog();
            }
        }

        private void disselectAllFilesToolStripMenuItem_Click(object sender, EventArgs e)
        {
            this.Close();
        }

        private void aboutToolStripMenuItem_Click(object sender, EventArgs e)
        {
            about_software();
        }


        private void about_software()
        {
            Form customForm = new Form
            {

                Text = "About Serpent + Twofish + AES File Encrypter",
                Size = new Size(860, 440),
                MinimumSize = new Size(640, 430),
                StartPosition = FormStartPosition.CenterScreen,
                BackColor = ColorTranslator.FromHtml("#7B08A5")
            };

            Label label = new Label
            {
                Text = "Serpent + Twofish + AES File Encrypter is an open-source software distributed under the MIT License.\n" +
                       "You are free to modify and distribute copies of the Serpent + Twofish + AES File Encrypter.\n" +
                       "You can use the Serpent + Twofish + AES File Encrypter in commercial applications.\n\n" +
                       "The Serpent + Twofish + AES File Encrypter app and its source code can be found on:\n\n" +
                       "SourceForge",
                ForeColor = ColorTranslator.FromHtml("#E4E3DF"),
                Font = new Font("Segoe UI", 12, FontStyle.Bold),
                AutoSize = true,
                TextAlign = ContentAlignment.MiddleCenter
            };
            customForm.Controls.Add(label);

            TextBox textField = new TextBox
            {
                Size = new Size(350, 30),
                Text = "sourceforge.net/p/sta-file-encrypter/",
                Location = new Point((customForm.ClientSize.Width - 200) / 2, label.Bottom + 12),
                Font = new Font("Segoe UI", 14),
                ReadOnly = true,
                BackColor = ColorTranslator.FromHtml("#2C2C2C"),
                ForeColor = ColorTranslator.FromHtml("#E4E3DF")
            };
            customForm.Controls.Add(textField);

            Label label1 = new Label
            {
                Location = new Point((customForm.ClientSize.Width - 200) / 2, textField.Bottom + 15),
                Text = "Github",
                ForeColor = ColorTranslator.FromHtml("#E4E3DF"),
                Font = new Font("Segoe UI", 12, FontStyle.Bold),
                AutoSize = true,
                TextAlign = ContentAlignment.MiddleCenter
            };
            customForm.Controls.Add(label1);

            TextBox textField1 = new TextBox
            {
                Size = new Size(540, 30),
                Text = "github.com/Northstrix/Serpent-Twofish-AES-File-Encrypter",
                Location = new Point((customForm.ClientSize.Width - 200) / 2, label1.Bottom + 6),
                Font = new Font("Segoe UI", 14),
                ReadOnly = true,
                BackColor = ColorTranslator.FromHtml("#2C2C2C"),
                ForeColor = ColorTranslator.FromHtml("#E4E3DF")
            };
            customForm.Controls.Add(textField1);

            Label label2 = new Label
            {
                Location = new Point((customForm.ClientSize.Width - 200) / 2, textField1.Bottom + 20),
                Text = "Copyright " + "\u00a9" + " 2024 Maxim Bortnikov",
                ForeColor = ColorTranslator.FromHtml("#E4E3DF"),
                Font = new Font("Segoe UI", 12, FontStyle.Bold),
                AutoSize = true,
                TextAlign = ContentAlignment.MiddleCenter
            };
            customForm.Controls.Add(label2);

            Button continueButton = new Button
            {
                Text = "Got It",
                Size = new Size(120, 38),
                Location = new Point((customForm.ClientSize.Width - 200) / 2, label2.Bottom + 30),
                BackColor = ColorTranslator.FromHtml("#4113AA"),
                ForeColor = ColorTranslator.FromHtml("#E4E3DF"),
                DialogResult = DialogResult.Yes,
                FlatStyle = FlatStyle.Flat,
                Font = new Font("Segoe UI", 12, FontStyle.Bold)
            };
            customForm.Controls.Add(continueButton);

            CenterLabelText(label, customForm);
            CenterLabelText(label1, customForm);
            CenterLabelText(label2, customForm);
            label.Location = new Point((customForm.ClientSize.Width - label.Width) / 2, +12);
            label1.Location = new Point((customForm.ClientSize.Width - label1.Width) / 2, textField.Bottom + 15);
            textField.Location = new Point((customForm.ClientSize.Width - textField.Width) / 2, label.Bottom + 10);
            textField1.Location = new Point((customForm.ClientSize.Width - textField1.Width) / 2, label1.Bottom + 6);
            label2.Location = new Point((customForm.ClientSize.Width - label2.Width) / 2, textField1.Bottom + 20);
            continueButton.Location = new Point((customForm.ClientSize.Width - continueButton.Width) / 2, label2.Bottom + 20);

            // Handle Resize event to adjust positions dynamically
            customForm.Resize += (sender, e) =>
            {
                CenterLabelText(label, customForm);
                CenterLabelText(label1, customForm);
                CenterLabelText(label2, customForm);
                label.Location = new Point((customForm.ClientSize.Width - label.Width) / 2, +12);
                label1.Location = new Point((customForm.ClientSize.Width - label1.Width) / 2, textField.Bottom + 15);
                textField.Location = new Point((customForm.ClientSize.Width - textField.Width) / 2, label.Bottom + 10);
                textField1.Location = new Point((customForm.ClientSize.Width - textField.Width) / 2, label1.Bottom + 6);
                label2.Location = new Point((customForm.ClientSize.Width - label2.Width) / 2, textField1.Bottom + 20);
                continueButton.Location = new Point((customForm.ClientSize.Width - continueButton.Width) / 2, label2.Bottom + 20);
            };
            customForm.ShowDialog();
        }

        private void Form1_Load(object sender, EventArgs e)
        {

        }
    }


    public partial class ViewAllFiles : Form
    {

        public ViewAllFiles(string[] data)
        {
            InitializeComponent(data);
            this.Text = "Selected Files";
        }

        private void InitializeComponent(string[] data)
        {
            this.SuspendLayout();

            this.AutoScaleDimensions = new System.Drawing.SizeF(96F, 96F);
            this.AutoScaleMode = System.Windows.Forms.AutoScaleMode.Dpi;
            this.ClientSize = new System.Drawing.Size(800, 600); // Set initial form size
            this.MinimumSize = new System.Drawing.Size(300, 200);
            this.BackColor = System.Drawing.ColorTranslator.FromHtml("#242424");

            TableLayoutPanel mainTable = new TableLayoutPanel
            {
                Dock = System.Windows.Forms.DockStyle.Fill,
                Padding = new System.Windows.Forms.Padding(10),
                AutoSize = true,
                CellBorderStyle = TableLayoutPanelCellBorderStyle.None // Set cell border style to None
            };

            // Set the row styles for the TableLayoutPanel
            mainTable.RowStyles.Add(new RowStyle(SizeType.Percent, 100)); // First row with 100% height
            mainTable.RowStyles.Add(new RowStyle(SizeType.Absolute, 40)); // Second row with 40px height

            this.Controls.Add(mainTable);

            // Create and add DataGridView
            DataGridView dataGridView = new DataGridView
            {
                AutoSizeColumnsMode = DataGridViewAutoSizeColumnsMode.Fill,
                BackgroundColor = System.Drawing.ColorTranslator.FromHtml("#161616"), // Updated background color
                ForeColor = System.Drawing.ColorTranslator.FromHtml("#EEEEEE"),
                Dock = System.Windows.Forms.DockStyle.Fill,
                AllowUserToAddRows = false,
                AllowUserToDeleteRows = false,
                AllowUserToOrderColumns = false,
                ReadOnly = true,
                ColumnHeadersHeightSizeMode = DataGridViewColumnHeadersHeightSizeMode.DisableResizing,
                CellBorderStyle = DataGridViewCellBorderStyle.None, // Set cell border style to None
                DefaultCellStyle = new DataGridViewCellStyle
                {
                    BackColor = System.Drawing.ColorTranslator.FromHtml("#161616"), // Set cell background color
                    ForeColor = System.Drawing.ColorTranslator.FromHtml("#EEEEEE"), // Set cell foreground color
                    Font = new System.Drawing.Font("Arial", 12) // Set text size for the table to 12
                },
                RowHeadersVisible = false // Hide row headers
            };

            // Customize the header style
            DataGridViewCellStyle headerStyle = new DataGridViewCellStyle
            {
                BackColor = System.Drawing.ColorTranslator.FromHtml("#24DE9C"), // Color scheme of the button
                Font = new System.Drawing.Font("Arial", 12, System.Drawing.FontStyle.Bold),
                ForeColor = System.Drawing.ColorTranslator.FromHtml("#202020")
            };
            dataGridView.ColumnHeadersDefaultCellStyle = headerStyle;

            // Add columns to DataGridView
            dataGridView.Columns.Add("File", "File");

            // Set column widths
            dataGridView.Columns["File"].Width = (int)(dataGridView.Width * 1);

            mainTable.Controls.Add(dataGridView, 0, 0);

            // Add data to DataGridView
            for (int i = 0; i < data.GetLength(0); i++)
            {
                dataGridView.Rows.Add(data[i]);
            }

            // Create and add OK button
            Button okButton = new Button
            {
                Text = "OK",
                FlatStyle = FlatStyle.Flat,
                Font = new System.Drawing.Font("Arial", 12, System.Drawing.FontStyle.Bold),
                BackColor = System.Drawing.ColorTranslator.FromHtml("#24DE9C"),
                ForeColor = System.Drawing.ColorTranslator.FromHtml("#202020"),
                Height = 40,
                Dock = System.Windows.Forms.DockStyle.Bottom,
                Margin = new System.Windows.Forms.Padding(0, 10, 0, 0),
                DialogResult = DialogResult.OK
            };

            okButton.FlatAppearance.BorderSize = 0; // Remove button border

            mainTable.Controls.Add(okButton, 0, 1);

            // Enable form resizing
            this.FormBorderStyle = FormBorderStyle.Sizable;
            this.MaximizeBox = true;

            this.ResumeLayout(false);
        }
    }


}