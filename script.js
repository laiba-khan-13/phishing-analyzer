function analyzeEmail() {
    const emailText = document.getElementById('emailInput').value.toLowerCase();
    const resultsDiv = document.getElementById('results');
    const findingsList = document.getElementById('findingsList');
    const scoreCircle = document.getElementById('scoreCircle');
    const scoreNumber = document.getElementById('scoreNumber');
    const scoreLabel = document.getElementById('scoreLabel');
    const recommendation = document.getElementById('recommendation');

    // Clear previous results
    findingsList.innerHTML = '';
    
    let score = 0;
    const findings = [];

    // ===== PHISHING CHECKS =====

    // 1. Check for suspicious sender (typos in domain)
    const suspiciousDomains = [
        'amaz0n', 'paypa1', 'g00gle', 'micros0ft', 'faceb00k',
        'apple-id', 'netfl1x', 'bank0famerica', 'chase-secure',
        'wells-fargo-alert', 'irs-gov'
    ];
    
    suspiciousDomains.forEach(domain => {
        if (emailText.includes(domain)) {
            findings.push({ type: 'danger', text: `🚨 Suspicious sender domain detected: "${domain}"` });
            score += 25;
        }
    });

    // 2. Check for urgent/scary words
    const urgentWords = ['urgent', 'immediate', 'suspend', 'suspended', 'locked', 'restricted', 
                         'verify now', 'act now', 'limited time', 'expires', 'warning', 
                         'alert', 'unusual activity', 'unauthorized', 'breach'];
    
    urgentWords.forEach(word => {
        if (emailText.includes(word)) {
            findings.push({ type: 'warning', text: `⚠️ Urgent/scary language: "${word}"` });
            score += 5;
        }
    });

    // 3. Check for requests for personal info
    const personalInfoRequests = ['password', 'ssn', 'social security', 'credit card', 
                                   'bank account', 'routing number', 'pin', 'verify your identity',
                                   'confirm your details', 'update your information'];
    
    personalInfoRequests.forEach(request => {
        if (emailText.includes(request)) {
            findings.push({ type: 'danger', text: `🚨 Requests personal info: "${request}"` });
            score += 20;
        }
    });

    // 4. Check for suspicious links
    const suspiciousLinkPatterns = [
        'bit.ly', 'tinyurl', 't.co', 'goo.gl', 'ow.ly',
        'http://'  // Unsecured links (not https)
    ];
    
    suspiciousLinkPatterns.forEach(pattern => {
        if (emailText.includes(pattern)) {
            findings.push({ type: 'warning', text: `🔗 Suspicious link pattern: "${pattern}"` });
            score += 10;
        }
    });

    // Check for mismatched links (text says one thing, URL says another)
    const linkRegex = /<a[^>]*href=["']([^"']*)["'][^>]*>([^<]*)<\/a>/g;
    let match;
    while ((match = linkRegex.exec(emailText)) !== null) {
        const url = match[1].toLowerCase();
        const text = match[2].toLowerCase();
        if (text.includes('amazon') && !url.includes('amazon.com')) {
            findings.push({ type: 'danger', text: `🚨 Fake link! Text says "Amazon" but URL goes to: ${url}` });
            score += 30;
        }
    }

    // 5. Check for poor grammar/spelling (simple check)
    const commonTypos = ['dear customer', 'dear user', 'valued costumer', 'acount', 'verificaton',
                         'suspicius', 'immediatly', 'confidental'];
    
    commonTypos.forEach(typo => {
        if (emailText.includes(typo)) {
            findings.push({ type: 'info', text: `📝 Possible typo/poor grammar: "${typo}"` });
            score += 3;
        }
    });

    // 6. Check for generic greetings
    const genericGreetings = ['dear customer', 'dear user', 'dear member', 'dear account holder',
                              'to whom it may concern'];
    
    genericGreetings.forEach(greeting => {
        if (emailText.includes(greeting)) {
            findings.push({ type: 'info', text: `👤 Generic greeting: "${greeting}"` });
            score += 5;
        }
    });

    // 7. Check for threats
    const threats = ['account will be closed', 'legal action', 'prosecuted', 'fined',
                     'arrest warrant', 'lawsuit', 'permanently disabled'];
    
    threats.forEach(threat => {
        if (emailText.includes(threat)) {
            findings.push({ type: 'danger', text: `🚨 Threat detected: "${threat}"` });
            score += 15;
        }
    });

    // 8. Check for attachments mention
    if (emailText.includes('attachment') || emailText.includes('attached file') || emailText.includes('.zip') || emailText.includes('.exe')) {
        findings.push({ type: 'warning', text: `📎 Email mentions attachments - be careful!` });
        score += 10;
    }

    // Cap score at 100
    score = Math.min(score, 100);

    // ===== DISPLAY RESULTS =====

    // Show results section
    resultsDiv.classList.remove('hidden');

    // Update score
    scoreNumber.textContent = score;

    // Determine risk level
    let riskLevel;
    if (score < 30) {
        riskLevel = 'safe';
        scoreLabel.textContent = '✅ Likely Safe';
        recommendation.textContent = 'This email looks legitimate, but always stay cautious!';
    } else if (score < 70) {
        riskLevel = 'warning';
        scoreLabel.textContent = '⚠️ Suspicious';
        recommendation.textContent = 'This email has some red flags. Be careful and verify with the sender!';
    } else {
        riskLevel = 'danger';
        scoreLabel.textContent = '🚨 HIGH RISK - Phishing!';
        recommendation.textContent = 'DO NOT CLICK ANY LINKS OR DOWNLOAD ATTACHMENTS! Delete this email!';
    }

    // Update colors
    scoreCircle.className = `score-circle ${riskLevel}`;
    scoreLabel.className = `score-label ${riskLevel}`;
    recommendation.className = `recommendation ${riskLevel}`;

    // Display findings
    if (findings.length === 0) {
        findingsList.innerHTML = '<div class="finding safe">✅ No suspicious patterns found!</div>';
    } else {
        findings.forEach(finding => {
            const div = document.createElement('div');
            div.className = `finding ${finding.type}`;
            div.textContent = finding.text;
            findingsList.appendChild(div);
        });
    }
}