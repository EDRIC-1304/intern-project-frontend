/* eslint-env browser, node */
/* global BigInt */
import React, { useState, useEffect, useCallback } from 'react';
import { ethers } from 'ethers';
import axios from 'axios';
import QRCode from 'react-qr-code';
import './appln.css'; // Using the new CSS file

// --- Constants ---
const BACKEND_URL = 'https://wallet-backend-g6nz.onrender.com';
const USDT_CONTRACT_ADDRESS = '0x787A697324dbA4AB965C58CD33c13ff5eeA6295F';
const USDC_CONTRACT_ADDRESS = '0x342e3aA1248AB77E319e3331C6fD3f1F2d4B36B1';
const ABI = ["function balanceOf(address) view returns (uint256)", "function transfer(address to, uint amount) returns (bool)"];
const defaultProvider = new ethers.JsonRpcProvider("https://data-seed-prebsc-1-s1.binance.org:8545");

// --- Loader Component ---
function Loader() {
  return (
    <div className="loader-overlay">
      <div className="loader-spinner"></div>
    </div>
  );
}

// --- Login Page Component ---
function LoginPage({ onLogin, showPopup, setIsLoading }) {
  const [walletName, setWalletName] = useState('');
  const [password, setPassword] = useState('');
  const [importMnemonic, setImportMnemonic] = useState('');
  const [authView, setAuthView] = useState('find'); 

  const checkIfUserExists = async (username) => {
    try {
      await axios.get(`${BACKEND_URL}/api/wallets/${username}`);
      return true;
    } catch (error) {
      if (error.response && error.response.status === 404) return false;
      throw new Error("A server error occurred while checking the username.");
    }
  };

  // --- FIXED --- This function now correctly handles password verification for all actions.
  const handleAction = async (action) => {
    setIsLoading(true);
    try {
      if (!walletName.trim()) throw new Error("Wallet Name cannot be empty.");
      if (!password.trim()) throw new Error("Password cannot be empty.");

      if (action === 'find') {
        const res = await axios.get(`${BACKEND_URL}/api/wallets/${walletName}`);
        const found = res.data;
        
        // The critical step: Verify the password before logging in.
        try {
            await ethers.Wallet.fromEncryptedJson(found.encryptedJson, password);
        } catch (e) {
            throw new Error("Wrong password for this wallet.");
        }

        const walletData = { 
            name: found.username, 
            address: found.address, 
            mnemonic: { phrase: found.mnemonic }, 
            encryptedJson: found.encryptedJson 
        };
        onLogin(walletData, password); // Pass the correct, verified password.
        showPopup("✅ Wallet fetched successfully!");

      } else { // Handles 'create' and 'import'
        const userExists = await checkIfUserExists(walletName);
        if (userExists) throw new Error("Username already exists. Please choose another.");
        
        let newWallet;
        if (action === 'create') {
            const created = ethers.Wallet.createRandom();
            const encryptedJson = await created.encrypt(password);
            await axios.post(`${BACKEND_URL}/api/wallets`, { userId: 'user001', username: walletName, address: created.address, mnemonic: created.mnemonic.phrase, encryptedJson });
            newWallet = { ...created, encryptedJson, name: walletName };
            showPopup("✅ Wallet created successfully!");
        } else { // action === 'import'
            if (!importMnemonic) throw new Error("Mnemonic phrase is required to import.");
            if (!ethers.Mnemonic.isValidMnemonic(importMnemonic)) throw new Error("Invalid Mnemonic Phrase.");
            const imported = ethers.Wallet.fromPhrase(importMnemonic);
            const encryptedJson = await imported.encrypt(password);
            await axios.post(`${BACKEND_URL}/api/wallets`, { userId: 'user001', username: walletName, address: imported.address, mnemonic: imported.mnemonic.phrase, encryptedJson });
            newWallet = { ...imported, encryptedJson, name: walletName };
            showPopup("✅ Wallet imported successfully!");
        }
        onLogin(newWallet, password);
      }
    } catch (error) {
        if (error.message.includes("Wrong password")) {
            showPopup(`❌ ${error.message}`);
        } else if (action === 'find' && error.response && error.response.status === 404) {
             showPopup(`❌ Wallet not found.`);
        } else {
            showPopup(`❌ ${error.message || "An error occurred."}`);
        }
    } finally {
      setIsLoading(false);
    }
  };

  return (
    <div className="auth-container">
        <div className="wallet-card auth-card">
        <div className="auth-header">
          <h1>REACT WALLET</h1>
          <p>Access or create your secure wallet</p>
        </div>
        <div className="view-buttons auth-toggle">
          <button className={`btn-view ${authView === 'find' ? 'active' : ''}`} onClick={() => setAuthView('find')}>Find</button>
          <button className={`btn-view ${authView === 'create' ? 'active' : ''}`} onClick={() => setAuthView('create')}>Create</button>
          <button className={`btn-view ${authView === 'import' ? 'active' : ''}`} onClick={() => setAuthView('import')}>Import</button>
        </div>
        {authView === 'import' && (
          <div className="input-group">
            <textarea placeholder="Enter your 12 or 24-word mnemonic phrase" value={importMnemonic} onChange={(e) => setImportMnemonic(e.target.value)} className="wallet-input" rows="3"/>
          </div>
        )}
        <div className="input-group">
          <input placeholder={authView === 'import' ? "Enter a NEW Username for this App" : "Enter Wallet Name"} value={walletName} onChange={(e) => setWalletName(e.target.value)} className="wallet-input"/>
        </div>
        <div className="input-group">
            <input type="password" placeholder="Enter Password" value={password} onChange={(e) => setPassword(e.target.value)} className="wallet-input"/>
        </div>
        <button className="btn btn-primary btn-full" onClick={() => handleAction(authView)}>
          {authView.charAt(0).toUpperCase() + authView.slice(1)} Wallet
        </button>
      </div>
    </div>
  );
}


// --- Main Application ---
function Appln() {
  const [wallet, setWallet] = useState(null);
  const [password, setPassword] = useState('');
  const [privateKey, setPrivateKey] = useState('');
  const [mnemonic, setMnemonic] = useState('');
  const [amount, setAmount] = useState('');
  const [recipientAddress, setRecipientAddress] = useState('');
  const [selectedToken, setSelectedToken] = useState('BNB');
  const [bnb, setBNB] = useState('0');
  const [usdt, setUSDT] = useState('0');
  const [usdc, setUSDC] = useState('0');
  const [view, setView] = useState('ledger');
  const [txHash, setTxHash] = useState('');
  const [popup, setPopup] = useState('');
  const [ledger, setLedger] = useState([]);
  const [disableSend, setDisableSend] = useState(false);
  const [sending, setSending] = useState(false);
  const [pendingTxs, setPendingTxs] = useState([]);
  const [cancellingTxHash, setCancellingTxHash] = useState(null);
  const [provider, setProvider] = useState(defaultProvider);
  const [isLoading, setIsLoading] = useState(true);

  useEffect(() => {
    try {
      const savedWalletJSON = localStorage.getItem('react-wallet-data');
      const savedPassword = localStorage.getItem('react-wallet-password');
      if (savedWalletJSON && savedPassword) {
        const savedWallet = JSON.parse(savedWalletJSON);
        setWallet(savedWallet);
        setPassword(savedPassword);
      }
    } catch (e) {
      // If parsing fails, clear the bad data
      localStorage.clear();
    }
    setIsLoading(false);
  }, []);

  const showPopup = (msg) => {
    setPopup(msg);
    setTimeout(() => setPopup(''), 3500);
  };

  // --- FIXED --- This function now safely handles server errors or empty responses.
  const fetchLedger = useCallback(async (address) => {
    if (!address) return;
    try {
      const res = await axios.get(`${BACKEND_URL}/api/transactions/${address}`);
      if (Array.isArray(res.data)) {
        setLedger(res.data);
      } else {
        setLedger([]); 
      }
    } catch {
      setLedger([]);
    }
  }, []);

  const updateBalances = useCallback(async (address) => {
    try {
      const b = await provider.getBalance(address);
      setBNB(ethers.formatEther(b));
      const usdtC = new ethers.Contract(USDT_CONTRACT_ADDRESS, ABI, provider);
      const usdtB = await usdtC.balanceOf(address);
      setUSDT(ethers.formatUnits(usdtB, 18));
      const usdcC = new ethers.Contract(USDC_CONTRACT_ADDRESS, ABI, provider);
      const usdcB = await usdcC.balanceOf(address);
      setUSDC(ethers.formatUnits(usdcB, 18));
    } catch (error) {
      console.error("Failed to update balances:", error);
      showPopup("❌ Could not fetch balances.");
    }
  }, [provider]);

  useEffect(() => {
    if (wallet?.address) {
      updateBalances(wallet.address);
      fetchLedger(wallet.address);
      setPrivateKey('');
      setMnemonic('');
    }
  }, [wallet, updateBalances, fetchLedger]);

  const revealPrivateKey = async () => {
    if (!wallet || !password) return showPopup("Enter password to reveal key.");
    setIsLoading(true);
    try {
      const dec = await ethers.Wallet.fromEncryptedJson(wallet.encryptedJson, password);
      setPrivateKey(dec.privateKey);
    } catch {
      showPopup("❌ Wrong password.");
    } finally {
      setIsLoading(false);
    }
  };
  
  const revealMnemonic = async () => {
    if (!wallet || !password) return showPopup("Enter password to reveal mnemonic.");
    setIsLoading(true);
    try {
      await ethers.Wallet.fromEncryptedJson(wallet.encryptedJson, password);
      setMnemonic(wallet.mnemonic.phrase);
    } catch {
      showPopup("❌ Wrong password.");
    } finally {
      setIsLoading(false);
    }
  };

  const sendToken = async () => {
    if (!wallet || !password || !recipientAddress || !amount) {
      return showPopup("❌ Please fill all fields to send.");
    }
    setIsLoading(true);
    setDisableSend(true);
    setSending(true);
    let tx;
    try {
      const dec = await ethers.Wallet.fromEncryptedJson(wallet.encryptedJson, password);
      const connected = dec.connect(provider);
      let contractAddress;
      if (selectedToken === "USDT") contractAddress = USDT_CONTRACT_ADDRESS;
      else if (selectedToken === "USDC") contractAddress = USDC_CONTRACT_ADDRESS;
  
      if (selectedToken === "BNB") {
        tx = await connected.sendTransaction({ to: recipientAddress, value: ethers.parseEther(amount) });
      } else {
        const contract = new ethers.Contract(contractAddress, ABI, connected);
        tx = await contract.transfer(recipientAddress, ethers.parseUnits(amount, 18));
      }
  
      setTxHash(tx.hash);
      const pendingTxData = { hash: tx.hash, amount, token: selectedToken, to: recipientAddress };
      setPendingTxs(prev => [...prev, pendingTxData]);
      showPopup("⏳ Transaction Submitted! Awaiting confirmation...");
      await tx.wait();
      await axios.post(`${BACKEND_URL}/api/transactions/record`, { txHash: tx.hash });
      showPopup("✅ Transaction Confirmed & Recorded!");
      updateBalances(await connected.getAddress());
      fetchLedger(await connected.getAddress());
    } catch (err) {
      showPopup("❌ Transaction Failed or was Rejected.");
    } finally {
      if (tx) setPendingTxs(prev => prev.filter(p => p.hash !== tx.hash));
      setSending(false);
      setDisableSend(false);
      setIsLoading(false);
    }
  };
  
  const handleCancelTransaction = async (stuckTxHash) => {
    if (!wallet || !password) return showPopup("❌ Enter password to sign cancellation.");
    setIsLoading(true);
    setCancellingTxHash(stuckTxHash);
    try {
      const decryptedWallet = await ethers.Wallet.fromEncryptedJson(wallet.encryptedJson, password);
      const connectedWallet = decryptedWallet.connect(provider);
      //...
    } catch (err) {
      showPopup(`❌ Cancellation failed: ${err.message}`);
    } finally {
      setCancellingTxHash(null);
      setIsLoading(false);
    }
  };

  const logout = () => {
    setWallet(null);
    setPassword('');
    //... (reset all other states)
    localStorage.removeItem('react-wallet-data');
    localStorage.removeItem('react-wallet-password');
    showPopup("✅ Logged out successfully!");
  };

  const onLogin = (loggedInWallet, loggedInPassword) => {
    setWallet(loggedInWallet);
    setPassword(loggedInPassword);
    localStorage.setItem('react-wallet-data', JSON.stringify(loggedInWallet));
    localStorage.setItem('react-wallet-password', loggedInPassword);
  };

  if (isLoading) return <Loader />;

  if (!wallet) {
    return (
      <>
        <LoginPage onLogin={onLogin} showPopup={showPopup} setIsLoading={setIsLoading} />
        {popup && <div className="wallet-popup">{popup}</div>}
      </>
    );
  }

  return (
    <div className="wallet-manager-container">
      {isLoading && <Loader />}
      <div className="header">
        <h1>DASHBOARD</h1>
        <button className="btn btn-secondary" onClick={logout}>Logout</button>
      </div>
      <div className="card-grid">
        <div className="card-column">
          <div className="wallet-card">
            <h3>{wallet.name}</h3>
            <p className="wallet-address"><strong>Address:</strong> {wallet.address}</p>
            <div className="balances">
              <p><strong>BNB:</strong> {parseFloat(bnb).toFixed(4)}</p>
              <p><strong>USDT:</strong> {parseFloat(usdt).toFixed(2)}</p>
              <p><strong>USDC:</strong> {parseFloat(usdc).toFixed(2)}</p>
            </div>
            {/* The password input is now in the main Appln state, so it's always available */}
            <div className="input-group">
               <input type="password" placeholder="Password for Actions" value={password} onChange={(e) => setPassword(e.target.value)} className="wallet-input"/>
            </div>
            <div className="button-row">
                <button className="btn btn-secondary btn-full" onClick={revealMnemonic}>Reveal Mnemonic</button>
                <button className="btn btn-secondary btn-full" onClick={revealPrivateKey}>Reveal Private Key</button>
            </div>
            {mnemonic && <p className="private-key"><strong>Mnemonic:</strong> {mnemonic}</p>}
            {privateKey && <p className="private-key"><strong>PK:</strong> {privateKey}</p>}
          </div>
          <div className="wallet-card">
            <div className="view-buttons">
              <button className={`btn-view ${view === 'ledger' ? 'active' : ''}`} onClick={() => { setView('ledger'); fetchLedger(wallet.address); }}>Ledger</button>
              <button className={`btn-view ${view === 'send' ? 'active' : ''}`} onClick={() => setView('send')}>Send</button>
              <button className={`btn-view ${view === 'receive' ? 'active' : ''}`} onClick={() => setView('receive')}>Receive</button>
            </div>
          </div>
        </div>
        <div className="card-column">
          {view === 'send' && (
            <div className="wallet-card">
              <h3>Send Tokens</h3>
              <input placeholder="Recipient Address" value={recipientAddress} onChange={(e) => setRecipientAddress(e.target.value)} className="wallet-input"/>
              <div className="amount-group">
                <input placeholder="Amount" value={amount} onChange={(e) => setAmount(e.target.value)} className="wallet-input amount-input"/>
                <select value={selectedToken} onChange={(e) => setSelectedToken(e.target.value)} className="wallet-select">
                  <option value="BNB">BNB</option>
                  <option value="USDT">USDT</option>
                  <option value="USDC">USDC</option>
                </select>
              </div>
              <button onClick={sendToken} className="btn btn-primary btn-full" disabled={disableSend || sending}>
                {sending ? "Sending..." : "Send Transaction"}
              </button>
            </div>
          )}
          {view === 'receive' && (
             <div className="wallet-card">
              <h3>Receive Funds</h3>
              <div className="receive-content">
                <div className="qr-code-bg"><QRCode value={wallet.address} size={160} bgColor="#ffffff" fgColor="#000000" /></div>
                <code className="wallet-address-code">{wallet.address}</code>
                <button className="btn btn-secondary" onClick={() => { navigator.clipboard.writeText(wallet.address); showPopup("📋 Address Copied") }}>Copy Address</button>
              </div>
            </div>
          )}
          {view === 'ledger' && (
            <div className="wallet-card">
              <h3>Transaction Ledger</h3>
              <div className="ledger-list">
                {pendingTxs.map(tx => (
                  <div key={tx.hash} className="ledger-item pending-item">
                    <p><strong>Sending:</strong> {tx.amount} {tx.token} to {tx.to.substring(0, 10)}...</p>
                    <div className="pending-details">
                      <div className="spinner"></div><span>Pending...</span>
                      <a href={`https://testnet.bscscan.com/tx/${tx.hash}`} target="_blank" rel="noopener noreferrer" className="appln-link">View</a>
                      <button className="btn-cancel" onClick={() => handleCancelTransaction(tx.hash)} disabled={cancellingTxHash === tx.hash}>{cancellingTxHash === tx.hash ? '...' : 'Cancel'}</button>
                    </div>
                  </div>
                ))}
                {ledger.length === 0 && pendingTxs.length === 0 ? <p>No transactions found.</p> : ledger.map((tx, i) => (
                  <div key={i} className="ledger-item">
                    <p><strong>From:</strong> {tx.from}</p><p><strong>To:</strong> {tx.to}</p>
                    <p><strong>Amount:</strong> {tx.amount} {tx.token}</p>
                    <p><strong>Time:</strong> {new Date(tx.timestamp).toLocaleString()}</p>
                    <a href={`https://testnet.bscscan.com/tx/${tx.txHash}`} target="_blank" rel="noopener noreferrer" className="appln-link">View on BscScan</a>
                  </div>
                ))}
              </div>
            </div>
          )}
        </div>
      </div>
      {popup && <div className="wallet-popup">{popup}</div>}
    </div>
  );
}

export default Appln;
