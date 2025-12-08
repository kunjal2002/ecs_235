const { useState, useEffect } = React;

// API Configuration
const API_BASE_URL = 'http://localhost:8081/api';

// Main App Component
function App() {
    const [analysisResults, setAnalysisResults] = useState([]);
    const [loading, setLoading] = useState(false);
    const [error, setError] = useState(null);
    const [queryCount, setQueryCount] = useState(100);
    const [successMessage, setSuccessMessage] = useState(null);
    const [stats, setStats] = useState({
        totalThreats: 0,
        totalQueries: 0,
        criticalThreats: 0,
        avgRiskScore: 0
    });

    // Calculate stats from analysis results
    useEffect(() => {
        if (analysisResults.length > 0) {
            const allThreats = analysisResults.flatMap(result => result.threats || []);
            const totalThreats = allThreats.length;
            const totalQueries = analysisResults.reduce((sum, result) => sum + (result.queriesAnalyzed || 0), 0);
            const criticalThreats = allThreats.filter(t => t.riskScore >= 90).length;
            const avgRiskScore = allThreats.length > 0 
                ? Math.round(allThreats.reduce((sum, t) => sum + t.riskScore, 0) / allThreats.length)
                : 0;

            setStats({
                totalThreats,
                totalQueries,
                criticalThreats,
                avgRiskScore
            });
        }
    }, [analysisResults]);

    const generateDataset = async () => {
        setLoading(true);
        setError(null);
        setSuccessMessage(null);
        setAnalysisResults([]); // Clear previous analysis results
        try {
            const response = await fetch(`${API_BASE_URL}/dataset/generate?queryCount=${queryCount}`, {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json'
                }
            });
            
            if (!response.ok) {
                throw new Error('Failed to generate dataset');
            }
            
            const data = await response.text();
            console.log('Dataset generated:', data);
            setSuccessMessage(`✅ Successfully generated ${queryCount} DNS queries! Click "Run Analysis" to detect threats.`);
            return true;
        } catch (err) {
            setError(`Error generating dataset: ${err.message}`);
            return false;
        } finally {
            setLoading(false);
        }
    };

    const runAnalysis = async () => {
        setLoading(true);
        setError(null);
        setSuccessMessage(null);
        try {
            const response = await fetch(`${API_BASE_URL}/detection/analysis`, {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json'
                }
            });
            
            if (!response.ok) {
                throw new Error('Failed to run analysis');
            }
            
            const data = await response.json();
            console.log('Analysis response:', data);
            console.log('Number of attack responses:', Array.isArray(data) ? data.length : 1);
            if (Array.isArray(data) && data.length > 0) {
                const allThreats = data.flatMap(result => result.threats || []);
                console.log('Total threats detected:', allThreats.length);
                console.log('Threat types:', allThreats.map(t => t.type));
            }
            setAnalysisResults(Array.isArray(data) ? data : [data]);
            if (data.length === 0 || (data[0] && data[0].queriesAnalyzed === 0)) {
                setSuccessMessage('ℹ️ No data found. Click "Generate Dataset" first to create DNS queries.');
            }
        } catch (err) {
            setError(`Error running analysis: ${err.message}`);
            setAnalysisResults([]);
        } finally {
            setLoading(false);
        }
    };

    const handleGenerateAndAnalyze = async () => {
        setLoading(true);
        setError(null);
        setSuccessMessage(null);
        setAnalysisResults([]); // Clear previous results first
        try {
            // Generate dataset
            const generateResponse = await fetch(`${API_BASE_URL}/dataset/generate?queryCount=${queryCount}`, {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json'
                }
            });
            
            if (!generateResponse.ok) {
                throw new Error('Failed to generate dataset');
            }
            
            // Wait a bit for data to be processed
            await new Promise(resolve => setTimeout(resolve, 500));
            
            // Run analysis
            const analysisResponse = await fetch(`${API_BASE_URL}/detection/analysis`, {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json'
                }
            });
            
            if (!analysisResponse.ok) {
                throw new Error('Failed to run analysis');
            }
            
            const data = await analysisResponse.json();
            console.log('Generate & Analyze response:', data);
            console.log('Number of attack responses:', Array.isArray(data) ? data.length : 1);
            if (Array.isArray(data) && data.length > 0) {
                const allThreats = data.flatMap(result => result.threats || []);
                console.log('Total threats detected:', allThreats.length);
                console.log('Threat types:', allThreats.map(t => t.type));
            }
            setAnalysisResults(Array.isArray(data) ? data : [data]);
            setSuccessMessage(`✅ Generated ${queryCount} DNS queries and completed analysis!`);
        } catch (err) {
            setError(`Error: ${err.message}`);
            setAnalysisResults([]);
        } finally {
            setLoading(false);
        }
    };

    const getSeverityColor = (severity) => {
        switch (severity) {
            case 'CRITICAL': return 'CRITICAL';
            case 'HIGH': return 'HIGH';
            case 'MEDIUM': return 'MEDIUM';
            case 'LOW': return 'LOW';
            default: return 'LOW';
        }
    };

    const getRiskColor = (riskScore) => {
        if (riskScore >= 90) return 'critical';
        if (riskScore >= 70) return 'high';
        if (riskScore >= 40) return 'medium';
        return 'low';
    };

    const formatTimestamp = (timestamp) => {
        return new Date(timestamp).toLocaleString();
    };

    const getThreatIcon = (type) => {
        if (type.includes('RANDOM_SUBDOMAIN')) return 'fa-random';
        if (type.includes('NXDOMAIN')) return 'fa-exclamation-triangle';
        if (type.includes('FLOODING')) return 'fa-wave-square';
        if (type.includes('AMPLIFICATION')) return 'fa-broadcast-tower';
        if (type.includes('EXFILTRATION') || type.includes('TUNNELING')) return 'fa-file-export';
        return 'fa-shield-alt';
    };

    return (
        <div className="app-container">
            <header className="header">
                <h1>
                    <i className="fas fa-shield-alt"></i>
                    DNS-Based Intrusion Detection System
                </h1>
                <p>Real-time DNS traffic analysis and threat detection</p>
            </header>

            <div className="controls">
                <div className="input-group">
                    <label htmlFor="queryCount">Query Count:</label>
                    <input
                        id="queryCount"
                        type="number"
                        value={queryCount}
                        onChange={(e) => setQueryCount(parseInt(e.target.value) || 100)}
                        min="1"
                        max="10000"
                    />
                </div>
                <button 
                    className="btn btn-secondary" 
                    onClick={generateDataset}
                    disabled={loading}
                >
                    <i className="fas fa-database"></i>
                    Generate Dataset
                </button>
                <button 
                    className="btn btn-primary" 
                    onClick={runAnalysis}
                    disabled={loading}
                >
                    <i className="fas fa-search"></i>
                    Run Analysis
                </button>
                <button 
                    className="btn btn-primary" 
                    onClick={handleGenerateAndAnalyze}
                    disabled={loading}
                >
                    <i className="fas fa-play"></i>
                    Generate & Analyze
                </button>
            </div>

            {error && (
                <div className="error">
                    <i className="fas fa-exclamation-circle"></i>
                    <span>{error}</span>
                </div>
            )}

            {successMessage && (
                <div className="success">
                    <i className="fas fa-check-circle"></i>
                    <span>{successMessage}</span>
                </div>
            )}

            {analysisResults.length > 0 && (
                <div className="stats-grid">
                    <StatCard 
                        title="Total Threats"
                        value={stats.totalThreats}
                        icon="fa-exclamation-triangle"
                        color="var(--danger-color)"
                    />
                    <StatCard 
                        title="Queries Analyzed"
                        value={stats.totalQueries}
                        icon="fa-chart-line"
                        color="var(--primary-color)"
                    />
                    <StatCard 
                        title="Critical Threats"
                        value={stats.criticalThreats}
                        icon="fa-fire"
                        color="var(--critical-color)"
                    />
                    <StatCard 
                        title="Avg Risk Score"
                        value={stats.avgRiskScore}
                        icon="fa-gauge-high"
                        color={getRiskColor(stats.avgRiskScore) === 'critical' ? 'var(--critical-color)' : 
                               getRiskColor(stats.avgRiskScore) === 'high' ? 'var(--danger-color)' : 
                               getRiskColor(stats.avgRiskScore) === 'medium' ? 'var(--warning-color)' : 
                               'var(--secondary-color)'}
                    />
                </div>
            )}

            {loading && (
                <div className="loading">
                    <div className="spinner"></div>
                    <p>Processing...</p>
                </div>
            )}

            {!loading && analysisResults.length === 0 && !error && (
                <div className="empty-state">
                    <i className="fas fa-shield-alt"></i>
                    <h2>No Analysis Results</h2>
                    <p>Generate a dataset and run analysis to see threat detection results</p>
                </div>
            )}

            {analysisResults.map((result, index) => (
                <AttackResponseCard 
                    key={index} 
                    result={result} 
                    getSeverityColor={getSeverityColor}
                    getRiskColor={getRiskColor}
                    formatTimestamp={formatTimestamp}
                    getThreatIcon={getThreatIcon}
                />
            ))}
        </div>
    );
}

// Stat Card Component
function StatCard({ title, value, icon, color }) {
    return (
        <div className="stat-card">
            <h3>{title}</h3>
            <div className="value" style={{ color }}>
                <i className={`fas ${icon}`} style={{ fontSize: '2rem', marginRight: '0.5rem' }}></i>
                {value}
            </div>
        </div>
    );
}

// Attack Response Card Component
function AttackResponseCard({ result, getSeverityColor, getRiskColor, formatTimestamp, getThreatIcon }) {
    return (
        <div className="attack-response fade-in">
            <div className="attack-header">
                <div>
                    <div className="attack-type">
                        <i className="fas fa-bug"></i>
                        {result.attackType 
                            ? result.attackType.replace(/_/g, ' ').split(' ').map(word => 
                                word.charAt(0).toUpperCase() + word.slice(1).toLowerCase()
                              ).join(' ')
                            : 'Attack Detected'}
                    </div>
                    <div className="attack-meta">
                        <span>
                            <i className="fas fa-database"></i> {result.queriesAnalyzed} queries analyzed
                        </span>
                        <span>
                            <i className="fas fa-clock"></i> {result.analysisTimeMs}ms
                        </span>
                        <span>
                            <i className="fas fa-calendar"></i> {formatTimestamp(result.timestamp)}
                        </span>
                    </div>
                </div>
                <div>
                    <div className={`severity-badge ${getSeverityColor(result.severity)}`}>
                        {result.severity}
                    </div>
                    <div className="risk-score" style={{ marginTop: '1rem' }}>
                        <span style={{ fontSize: '0.875rem', color: 'var(--text-secondary)' }}>Risk Score:</span>
                        <div className="risk-bar">
                            <div 
                                className={`risk-fill ${getRiskColor(result.riskScore)}`}
                                style={{ width: `${result.riskScore}%` }}
                            ></div>
                        </div>
                        <span style={{ fontWeight: 600 }}>{result.riskScore}</span>
                    </div>
                </div>
            </div>

            {result.threats && result.threats.length > 0 && (
                <div className="threats-grid">
                    {result.threats.map((threat, idx) => (
                        <ThreatCard 
                            key={idx}
                            threat={threat}
                            getRiskColor={getRiskColor}
                            formatTimestamp={formatTimestamp}
                            getThreatIcon={getThreatIcon}
                        />
                    ))}
                </div>
            )}

            {result.recommendation && (
                <div className="recommendations">
                    <h3>
                        <i className="fas fa-lightbulb"></i>
                        Security Recommendations
                    </h3>
                    <div className="recommendations-content">
                        {result.recommendation.split('\n').map((line, idx) => {
                            // Check if line starts with a number (numbered list item)
                            const isNumberedItem = /^\d+\./.test(line.trim());
                            return (
                                <p key={idx} className={isNumberedItem ? 'recommendation-item' : ''}>
                                    {line.trim() || '\u00A0'}
                                </p>
                            );
                        })}
                    </div>
                </div>
            )}
        </div>
    );
}

// Threat Card Component
function ThreatCard({ threat, getRiskColor, formatTimestamp, getThreatIcon }) {
    // Format threat type for display
    const formatThreatType = (type) => {
        return type
            .replace(/_/g, ' ')
            .replace(/\bDNS\b/g, 'DNS')
            .replace(/\bNXDOMAIN\b/g, 'NXDOMAIN')
            .split(' ')
            .map(word => word.charAt(0).toUpperCase() + word.slice(1).toLowerCase())
            .join(' ');
    };

    return (
        <div className={`threat-card ${threat.type} ${getRiskColor(threat.riskScore)}`}>
            <div className="threat-header">
                <div className="threat-type">
                    <i className={`fas ${getThreatIcon(threat.type)}`}></i>
                    {formatThreatType(threat.type)}
                </div>
                <div className={`threat-risk risk-${getRiskColor(threat.riskScore)}`}>
                    <span>Risk Score: {threat.riskScore}</span>
                    <div className="threat-risk-bar">
                        <div 
                            className={`threat-risk-fill ${getRiskColor(threat.riskScore)}`}
                            style={{ width: `${threat.riskScore}%` }}
                        ></div>
                    </div>
                </div>
            </div>
            <div className="threat-description">
                {threat.description.split('\n').map((line, idx) => (
                    <p key={idx} style={{ margin: idx > 0 ? '0.5rem 0' : '0' }}>
                        {line}
                    </p>
                ))}
            </div>
            <div className="threat-source">
                <i className="fas fa-network-wired"></i>
                <strong>Source IP:</strong> {threat.sourceIp}
                {threat.timestamp && (
                    <span style={{ marginLeft: '1rem' }}>
                        <i className="fas fa-clock"></i> {formatTimestamp(threat.timestamp)}
                    </span>
                )}
            </div>
        </div>
    );
}

// Render App
ReactDOM.render(<App />, document.getElementById('root'));

