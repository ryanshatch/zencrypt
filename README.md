<!--
****************************************************************************************
Title: Zencrypt CLI Readme.md    *******************************************************
Developed by: Ryan Hatch         *******************************************************
Dev Date: Aug 10th 2022          *******************************************************
Last Updated: Oct 27th 2023      *******************************************************
Version: 2.0                     *******************************************************
****************************************************************************************
-->
<!DOCTYPE html>
<html>
  <body>
    <hr>
    <h1 align="center">Zencrypt</h1>
    <br>
    <p align="center">
      <strong>Hash and Cipher Command Line Interface:</strong>
<!--       <br>
      <strong>By: Ryan Hatch</strong> -->
      <br>
    </p>
    <p align="center">
      <a href="#introduction">Introduction</a> • <a href="#features">Features</a> • <a href="#installation">Installation</a> • <a href="#usage">Usage</a> • <a href="#examples">Examples</a> • <a href="#contributing">Contributing</a> • <a href="#disclaimer">Disclaimer</a> • <a href="#license">License</a> • <a href="#contact">Contact</a>
    </p>
    <hr>
    <p align="center">
<!--       <br> -->
      <strong>Developed By: Ryan Hatch</strong>
    <p align="center"> &copy; 2025 Ryan Hatch <br> All Rights Reserved.<br><i>This software is proprietary and owned by Ryan Hatch. Unauthorized use, modification, or distribution is prohibited.</i> </p>
    <h4>Last updated: Jan 20 2025 - Updated comments and added a more simple structure for the changes to be made.</h2>
    <h2 id="introduction">Introduction</h2>
    <p> This project provides a command-line interface for managing hashes and encryption for input text. It includes both a Python and a Java implementation along with a lite version in C++.</p>
    <ul>
    <li><h4>The <code>Python version</code> contains the full Zencrypt program that can provide functionality for hashing, encrypting text, encrypting files, along with full handling of PGP encryption.</h4></li>
    <li><h4>The <code>Python GUI</code>is a basic form of Zencrypt V2 with the same functionalities and shortcut commands, but with a GUI.</h4></li>
    <li><h4>The <code>Java version</code> is a clone copy of Zencrypt v3 with the inability to handle PGP encryption. All other functions remain the same.</h4></li>
    <li><h4>The <code>C++ version</code> only allows basic hashing and encryption functions.</h4>
    </ul></li>
    <h2 id="features">Features</h2>
    <ul>
      <li>
        <strong>Generate and verify hashes</strong> with optional salt.
      </li>
      <li>
        <strong>Encrypt and decrypt text.</strong>
<!--       </li> -->
      <!-- <li><strong>Verify hashes.</strong></li> -->
      <li>
        <strong>Encrypt and decrypt files.</strong>
      </li>
      <li>
        <strong>PGP Encryption</strong>
      </li>
    </ul>
    <h2 id="installation">Installation</h2>
    <p> To install Zencrypt, you will need to follow these steps: </p>
    <ol>
      <li>Clone the repository or download the source code with the command:<br><code>git clone https://github.com/ryanshatch/Zencrypt.git</code>. </li>
      <li>Navigate to the <code>Python CLI</code> or to the <code>Java CLI</code> directory. </li>
      <li>Install the required dependencies with the command: <code>pip install -r requirements.txt</code>. </li>
    </ol>
    <h2 id="usage">Usage</h2>
    <h3>Python Version</h3>
    <p> 1. After installing the required dependencies, you can run the script using the Python interpreter and running the command: <code>python zencrypt.py</code>
      <br> 2. Select whether you want to <code>hash, encrypt text, or parse files</code> and then follow the on screen instructions. <br>
      <br>To exit the program, simply enter <code>exit</code>.
    </p>
    <h2></h2>
    <h3>Java Version</h3>
    <p> 1. After installing the required dependencies, you can now compile and run the Java program with the commands: <code>javac Zencrypt.java</code> and <code>java Zencrypt</code>
      <br /> 2. Select whether you want to <code>hash, encrypt text, or parse files</code> and then simply just follow the on screen instructions. <br>
      <br>To exit the program, simply enter <code>exit</code>
    </p>
    <p align="center">
      <br>
      <br>
      <strong> Alternatively, you can avoid installing the dependancies by using the provided executable to run the binaries: <code>zencryptCLI.exe</code>
      </strong>
      <br />
      </strong>
      </br>
    </p>
    <h2 id="examples">Examples</h2>
    <h3 align="center">Hashing:</h3>
    <center>
      <img alt="Hashing Example" src="https://github.com/ryanshatch/Zencrypt/blob/main/zencrypthash.png" style="width: 100%; height: 100%;" />
    </center>
    <h3 align="center">Cipher:</h3>
    <center>
      <img alt="Cipher Example" src="https://github.com/ryanshatch/Zencrypt/blob/main/zencrypt.PNG" style="width: 100%; height: 100%;" />
    </center>
    <h3 align="center">Encrypting Parsed Files:</h3>
    <center>
      <img alt="Cipher Example" src="https://github.com/ryanshatch/Zencrypt/blob/main/encrypt.PNG" style="width: 100%; height: 50%;" />
    </center>
        <h3 align="center">PGP Encryption:</h3>
    <center>
      <img alt="Cipher Example" src="https://github.com/ryanshatch/Zencrypt/blob/main/pgpencryption.PNG" style="width: 100%; height: 50%;" />
    </center>
    </p>
    <hr><br>
    <hr><br>
    <h2 align="center" id="contributing">Contributing</h2>
    <ol>
      <p align="center">
        <strong>Please reach out to me to verify and validate your ideas and contributions before continuing any further. Although contributions may be welcome, it will be discussed first. <br>
          <br> After reaching out to me, please follow these steps: </strong>
        <br>
        <li>Fork the repository.</li>
        <li>Create a new branch with the command: <code>git checkout -b feature-branch</code>.
        <li>Make your changes.</li>
        <li>Commit your changes with the command: <code>git commit -am 'Add new feature'</code>.
        <li>Push to the branch with the command: <code>git push origin feature-branch</code>.
        <li>Create a new Pull Request.</li>
    </ol>
<!--     <h1></h1> -->
    <h1 align="center" id="disclaimer">DISCLAIMER!</h1>
    <p align="center">
      <strong>
        <=>
          <=>
            <=>
              <=>
                <=>
                  <=>
                    <=>
                      <=>
                        <=>
                          <=>
                            <=>
                              <=>
                                <=>
                                  <=>
                                    <=>
                                      <=>
                                        <=>
                                          <=>
                                            <=>
                                              <=>
                                                <=>
                                                  <=>
                                                    <=>
                                                      <=>
                                                        <=>
                                                          <=>
                                                            <!-- <=><=><=><=> -->
      </strong>
      </br>
      <!-- <p align="center"><strong><=><=><=></strong></br></p> -->
    <p align="center">
      <strong>
        <code>This script is provided for educational and demonstration purposes only. <br>Use it responsibly and please adhere to all applicable laws and regulations. </code>
      </strong>
      </br>
    </p>
    <!-- <strong>This script is provided for educational and demonstration purposes only. Use it responsibly and adhere to all applicable laws and regulations.</strong></br></p> -->
    <p align="center">
      <strong>
        <code>I am absolutely immune from any responsibility in regaurds to any damages or loss of data caused by the <br>use, abuse, or misuse of this software. </code>
      </strong>
      </br>
      <!-- <p align="center"><strong><=><=><=></strong></br></p> -->
    <p align="center">
      <strong>
        <=>
          <=>
            <=>
              <=>
                <=>
                  <=>
                    <=>
                      <=>
                        <=>
                          <=>
                            <=>
                              <=>
                                <=>
                                  <=>
                                    <=>
                                      <=>
                                        <=>
                                          <=>
                                            <=>
                                              <=>
                                                <=>
                                                  <=>
                                                    <=>
                                                      <=>
                                                        <=>
                                                          <=>
                                                            <!-- <=><=><=><=> -->
      </strong>
      </br>
    </p><hr>
    <h2 align="center" id="liscense">Liscense</h2>
    <p> This software is the property of the copyright holder and is protected by copyright laws. All rights are reserved. The copyright holder grants no implied or express license for the use, copying, modification, distribution, or reproduction of this software, in whole or in part, without the prior written permission of the copyright holder. </p>
    <p> Any unauthorized use, copying, modification, distribution, or reproduction of this software, in whole or in part, is strictly prohibited and constitutes a violation of copyright law. Such unauthorized use may result in civil and/or criminal penalties, including but not limited to legal action and monetary damages. </p>
    <p> To obtain permission for any use, copying, modification, distribution, or reproduction of this software, please contact the copyright holder at the following address: <code>ryan@rshatch.com</code>
    </p>
    </p>
    <br>
    <p align="center">
      <strong>
        <code>By using this software, you acknowledge that you have read and understood the terms of this license and agree to comply with all applicable copyright laws. <br>Failure to abide by the terms of this license may subject you to legal consequences. </code>
      </strong>
    </p>
  </body>
</html><hr>
<h2 align="center" id="contact">Contact</h2>
<p align="center">For any inquiries or suggestions, please contact me at <a href="mailto:ryan@rshatch.com">ryan@rshatch.com</a>.
</body>
</html>
