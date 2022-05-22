import { useState } from "react";

function App() {
    const [ signedInAddress, setSignedInAddress ] = useState('')

    async function handleLogin() {
        const { ethereum } = window

        await ethereum.request({ method: 'eth_requestAccounts'})
        const address = ethereum.selectedAddress

        let response = await fetch('/api/nonce', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ address }),
        })
        if (!response.ok) {
            throw new Error(response.statusText)
        }

        const body = await response.json()

        const signature = await ethereum.request({
            method: 'personal_sign',
            params: [ `0x${toHex(body.nonce)}`, address ],
        })

        response = await fetch('/api/verify-signature', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ address, signature }),
        })
        if (!response.ok) {
            throw new Error(response.statusText)
        }

        setSignedInAddress(address)
    }

    async function handleLogout() {
        setSignedInAddress('')
    }

    if (!isMetamaskAvailable()) {
        return (
            <div>Please install or enable Metamask to get started</div>
        )
    }

    return (
        <div>
            { !signedInAddress ?
                <button onClick={handleLogin}>
                    Sign in with Metamask
                </button>
                :
                <>
                    <p>Successfully signed in with Metamask!</p>
                    <p>ETH address {signedInAddress}</p>
                    <button onClick={handleLogout}>
                        Logout
                    </button>
                </>
            }
        </div>
    );
}

function toHex(input) {
    return input.split('').map((c) => c.charCodeAt(0).toString(16).padStart(2, '0')).join('');
}

function isMetamaskAvailable() {
    const { ethereum } = window
    return typeof ethereum !== 'undefined' && ethereum.isMetaMask
}

export default App;
