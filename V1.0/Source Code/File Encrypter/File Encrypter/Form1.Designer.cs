namespace File_Encrypter
{
    partial class Form1
    {
        /// <summary>
        ///  Required designer variable.
        /// </summary>
        private System.ComponentModel.IContainer components = null;

        /// <summary>
        ///  Clean up any resources being used.
        /// </summary>
        /// <param name="disposing">true if managed resources should be disposed; otherwise, false.</param>
        protected override void Dispose(bool disposing)
        {
            if (disposing && (components != null))
            {
                components.Dispose();
            }
            base.Dispose(disposing);
        }

        #region Windows Form Designer generated code

        /// <summary>
        ///  Required method for Designer support - do not modify
        ///  the contents of this method with the code editor.
        /// </summary>
        private void InitializeComponent()
        {
            menuStrip1 = new MenuStrip();
            fileToolStripMenuItem = new ToolStripMenuItem();
            selectFilesToolStripMenuItem = new ToolStripMenuItem();
            listSelectedFilesToolStripMenuItem = new ToolStripMenuItem();
            disselectAllFilesToolStripMenuItem = new ToolStripMenuItem();
            aboutToolStripMenuItem = new ToolStripMenuItem();
            menuStrip1.SuspendLayout();
            SuspendLayout();
            // 
            // menuStrip1
            // 
            menuStrip1.Items.AddRange(new ToolStripItem[] { fileToolStripMenuItem, aboutToolStripMenuItem });
            menuStrip1.Location = new Point(0, 0);
            menuStrip1.Name = "menuStrip1";
            menuStrip1.Size = new Size(784, 24);
            menuStrip1.TabIndex = 0;
            menuStrip1.Text = "menuStrip1";
            // 
            // fileToolStripMenuItem
            // 
            fileToolStripMenuItem.DropDownItems.AddRange(new ToolStripItem[] { selectFilesToolStripMenuItem, listSelectedFilesToolStripMenuItem, disselectAllFilesToolStripMenuItem });
            fileToolStripMenuItem.Name = "fileToolStripMenuItem";
            fileToolStripMenuItem.Size = new Size(37, 20);
            fileToolStripMenuItem.Text = "File";
            // 
            // selectFilesToolStripMenuItem
            // 
            selectFilesToolStripMenuItem.Name = "selectFilesToolStripMenuItem";
            selectFilesToolStripMenuItem.Size = new Size(165, 22);
            selectFilesToolStripMenuItem.Text = "Select Files";
            selectFilesToolStripMenuItem.Click += selectFilesToolStripMenuItem_Click;
            // 
            // listSelectedFilesToolStripMenuItem
            // 
            listSelectedFilesToolStripMenuItem.Name = "listSelectedFilesToolStripMenuItem";
            listSelectedFilesToolStripMenuItem.Size = new Size(165, 22);
            listSelectedFilesToolStripMenuItem.Text = "List Selected Files";
            listSelectedFilesToolStripMenuItem.Click += listSelectedFilesToolStripMenuItem_Click;
            // 
            // disselectAllFilesToolStripMenuItem
            // 
            disselectAllFilesToolStripMenuItem.Name = "disselectAllFilesToolStripMenuItem";
            disselectAllFilesToolStripMenuItem.Size = new Size(165, 22);
            disselectAllFilesToolStripMenuItem.Text = "Quit";
            disselectAllFilesToolStripMenuItem.Click += disselectAllFilesToolStripMenuItem_Click;
            // 
            // aboutToolStripMenuItem
            // 
            aboutToolStripMenuItem.Name = "aboutToolStripMenuItem";
            aboutToolStripMenuItem.Size = new Size(52, 20);
            aboutToolStripMenuItem.Text = "About";
            aboutToolStripMenuItem.Click += aboutToolStripMenuItem_Click;
            // 
            // Form1
            // 
            AutoScaleDimensions = new SizeF(7F, 15F);
            AutoScaleMode = AutoScaleMode.Font;
            ClientSize = new Size(784, 441);
            Controls.Add(menuStrip1);
            MainMenuStrip = menuStrip1;
            Name = "Form1";
            Text = "Serpent + Twofish + AES File Encrypter";
            Load += Form1_Load;
            menuStrip1.ResumeLayout(false);
            menuStrip1.PerformLayout();
            ResumeLayout(false);
            PerformLayout();
        }

        #endregion

        private MenuStrip menuStrip1;
        private ToolStripMenuItem fileToolStripMenuItem;
        private ToolStripMenuItem aboutToolStripMenuItem;
        private ToolStripMenuItem selectFilesToolStripMenuItem;
        private ToolStripMenuItem listSelectedFilesToolStripMenuItem;
        private ToolStripMenuItem disselectAllFilesToolStripMenuItem;
    }
}