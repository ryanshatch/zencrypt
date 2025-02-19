import React from 'react';
import ReactDOM from 'react-dom';

const Navbar = () => {
  return (
    <nav className="bg-black text-white p-4">
      <div className="max-w-7xl mx-auto">
        <div className="flex justify-between items-center">
          <div className="text-xl font-bold">Zencrypt v5.3-A2</div>
          
          <div className="flex space-x-2">
            <button className="px-3 py-1 bg-gray-800 hover:bg-gray-700 rounded">Hash</button>
            <button className="px-3 py-1 bg-gray-800 hover:bg-gray-700 rounded">Encrypt</button>
            <button className="px-3 py-1 bg-gray-800 hover:bg-gray-700 rounded">Decrypt</button>
            <button className="px-3 py-1 bg-gray-800 hover:bg-gray-700 rounded">File Operations</button>
            <button className="px-3 py-1 bg-gray-800 hover:bg-gray-700 rounded">Export Key</button>
            <button className="px-3 py-1 bg-gray-800 hover:bg-gray-700 rounded">Import Key</button>
            <button className="px-3 py-1 bg-gray-800 hover:bg-gray-700 rounded">Logout</button>
          </div>
        </div>
        
        <div className="mt-2 text-sm text-gray-400">
          © 2025 All rights reserved by 
          <a href="https://ryanshatch.com" className="text-blue-400 hover:text-blue-300 ml-1">
            Ryanshatch
          </a>
        </div>
      </div>
    </nav>
  );
};

export default Navbar;