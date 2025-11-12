import React from 'react';
import { Link } from 'react-router-dom';
import './MainPage.css';

const MainPage = () => {
    return (
        <div className="main-page-container">
            <header className="App-header">
                <h1>Tokamak-FROST</h1>
                <p>A web-based client for FROST Distributed Key Generation and Signing Ceremonies.</p>
            </header>
            <div className="ceremony-selection">
                <Link to="/dkg" className="ceremony-button">
                    <h2>Run DKG Ceremony</h2>
                    <p>Create a new set of threshold keys with a group of participants.</p>
                </Link>
                <Link to="/signing" className="ceremony-button">
                    <h2>Run Signing Ceremony</h2>
                    <p>Use an existing threshold key to collaboratively sign a message.</p>
                </Link>
            </div>
        </div>
    );
};

export default MainPage;
