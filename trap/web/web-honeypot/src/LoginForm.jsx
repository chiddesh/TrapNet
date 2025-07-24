import React, { useState } from 'react'

function LoginForm() {
    const [userName, setUserName] = useState("");
    const [password, setPassword] = useState("");

    const BACKEND_URL = process.env.REACT_APP_API_URL;

    const handleLogin = async (e) => {
        e.preventDefault();

        if (!userName || !password) {
            alert("Please fill in both fields");
            return;
        }

        try {
            const res = await fetch(`${BACKEND_URL}/web-log`, {
                method: "POST",
                headers: {
                    "Content-Type": "application/json"
                },
                body: JSON.stringify({ userName, password })
            });

            if (res.ok) {
                console.log("Login captured!");
            } else {
                console.error("Failed to log");
            }
        } catch (error) {
            console.log("Error:", error);
        }
    };

    return (
        <form onSubmit={handleLogin}>
            <label>Enter Username</label>
            <input
                onChange={(e) => setUserName(e.target.value)}
                placeholder='Username'
                type='text'
                required
            />
            <label>Enter Password</label>
            <input
                onChange={(e) => setPassword(e.target.value)}
                placeholder='Password'
                type='password'
                required
            />
            <button type='submit'>Login</button>
        </form>
    );
}

export default LoginForm;
