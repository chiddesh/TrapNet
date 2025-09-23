import React, { useState } from "react";

function Login() {
    const BACKEND_URL = import.meta.env.VITE_BACKEND_URL || "http://localhost:5000";
    const [username, setUsername] = useState("");
    const [password, setPassword] = useState("");
    const [loading, setLoading] = useState(false);

    async function handleLogin(e) {
        e.preventDefault();
        if (!username || !password) {
            alert("Please fill all the fields");
            return;
        }
        setLoading(true);
        try {
            const res = await fetch(`${BACKEND_URL}/log`, {
                method: "POST",
                headers: { "Content-Type": "application/json" },
                body: JSON.stringify({ username, password }),
            });
        } catch (error) {
            console.log("Error:", error.message);
        } finally {
            setLoading(false);
        }
    }

    return (
        <div className="min-h-screen bg-gradient-to-b from-amber-200 via-amber-100 to-amber-50 flex items-center justify-center p-6">
            <div className="w-full max-w-md">
                <div className="bg-white/90 backdrop-blur-md rounded-2xl shadow-xl ring-1 ring-amber-200 overflow-hidden">

                    <div className="px-6 py-8 sm:px-8 sm:py-10">
                        <div className="flex items-center gap-3">
                            <div className="w-12 h-12 rounded-xl bg-amber-600 flex items-center justify-center text-white font-bold text-lg shadow-md">
                                T
                            </div>
                            <div>
                                <h1 className="text-2xl sm:text-3xl font-semibold text-amber-900">TrapNet</h1>
                                <p className="text-sm text-amber-700/80">Sign in to continue</p>
                            </div>
                        </div>

                        <form onSubmit={handleLogin} className="mt-6 flex flex-col gap-4">
                            <label htmlFor="username" className="text-sm font-medium text-amber-800">
                                Username
                            </label>
                            <input
                                id="username"
                                name="username"
                                value={username}
                                onChange={(e) => setUsername(e.target.value)}
                                placeholder="e.g. admin"
                                type="text"
                                required
                                className="w-full px-4 py-2 rounded-lg border border-amber-200 focus:outline-none focus:ring-2 focus:ring-amber-400 focus:border-amber-400 placeholder:italic"
                                aria-label="Username"
                            />

                            <label htmlFor="password" className="text-sm font-medium text-amber-800">
                                Password
                            </label>
                            <input
                                id="password"
                                name="password"
                                value={password}
                                onChange={(e) => setPassword(e.target.value)}
                                placeholder="Password"
                                type="password"
                                required
                                className="w-full px-4 py-2 rounded-lg border border-amber-200 focus:outline-none focus:ring-2 focus:ring-amber-400 focus:border-amber-400 placeholder:italic"
                                aria-label="Password"
                            />

                            <button
                                type="submit"
                                disabled={loading}
                                className="mt-1 w-full inline-flex justify-center items-center gap-2 px-4 py-2 rounded-full bg-amber-700 text-white font-medium hover:bg-amber-800 active:scale-95 transition transform disabled:opacity-60"
                            >
                                {loading ? "Logging…" : "Login"}
                            </button>
                        </form>
                    </div>
                </div>
            </div>
        </div>
    );
}

export default Login;
