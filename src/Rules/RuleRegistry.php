<?php

declare(strict_types=1);

namespace EidCloud\SecretHunter\Rules;

/**
 * Built-in Secret Detection Rules Registry.
 *
 * Contains 30 high-precision regex signatures for detecting API keys,
 * cloud credentials, OAuth tokens, private keys, and database connection strings.
 */
class RuleRegistry
{
    /** @var array<string, Rule> */
    private array $rules = [];

    public function __construct()
    {
        $this->registerDefaults();
    }

    /**
     * Create an instance with all default rules pre-loaded.
     */
    public static function create(): self
    {
        return new self();
    }

    public function register(Rule $rule): void
    {
        $this->rules[$rule->id] = $rule;
    }

    public function unregister(string $id): void
    {
        unset($this->rules[$id]);
    }

    public function getRule(string $id): ?Rule
    {
        return $this->rules[$id] ?? null;
    }

    /**
     * @return array<string, Rule>
     */
    public function getAll(): array
    {
        return $this->rules;
    }

    public function count(): int
    {
        return count($this->rules);
    }

    /**
     * Register all 30 built-in rules.
     */
    private function registerDefaults(): void
    {
        // 1. OpenAI API Keys (legacy sk-, project sk-proj-, admin sk-admin-)
        $this->register(new Rule(
            id: 'openai-api-key',
            name: 'OpenAI API Key',
            pattern: '/(?<![a-zA-Z0-9_\-])(?:sk-proj-[a-zA-Z0-9_\-]{40,}|sk-admin-[a-zA-Z0-9_\-]{40,}|sk-[a-zA-Z0-9]{32,})(?![a-zA-Z0-9_\-])/',
            severity: Severity::CRITICAL,
            category: 'AI/ML',
            description: 'OpenAI API Secret Key or Project API Key'
        ));

        // 2. Anthropic Claude API Key
        $this->register(new Rule(
            id: 'anthropic-api-key',
            name: 'Anthropic API Key',
            pattern: '/(?<![A-Za-z0-9_\-])sk-ant-api[0-9]{2}-[a-zA-Z0-9_\-]{80,105}(?![A-Za-z0-9_\-])/',
            severity: Severity::CRITICAL,
            category: 'AI/ML',
            description: 'Anthropic Claude API Secret Key'
        ));

        // 3. AWS Access Key ID
        $this->register(new Rule(
            id: 'aws-access-key-id',
            name: 'AWS Access Key ID',
            pattern: '/(?<![A-Z0-9])(?:AKIA|ABIA|ACCA|ASIA)[0-9A-Z]{16}(?![A-Z0-9])/',
            severity: Severity::CRITICAL,
            category: 'Cloud Provider',
            description: 'Amazon Web Services 20-character Access Key ID'
        ));

        // 4. AWS Secret Access Key
        $this->register(new Rule(
            id: 'aws-secret-access-key',
            name: 'AWS Secret Access Key',
            pattern: '/(?i)(?:aws_secret_access_key|aws_secret_key|secret_access_key)\s*[:=]\s*[\'"]?([0-9a-zA-Z\/+]{40})[\'"]?/',
            severity: Severity::CRITICAL,
            category: 'Cloud Provider',
            description: 'Amazon Web Services 40-character Secret Access Key',
            entropyThreshold: 3.5,
            matchGroup: 1
        ));

        // 5. Google Cloud Platform API Key
        $this->register(new Rule(
            id: 'google-cloud-api-key',
            name: 'Google Cloud API Key',
            pattern: '/(?<![A-Za-z0-9_\-])AIza[0-9A-Za-z\-_]{35}(?![A-Za-z0-9_\-])/',
            severity: Severity::CRITICAL,
            category: 'Cloud Provider',
            description: 'Google Cloud Platform AIza API Key'
        ));

        // 6. Google OAuth Access Token
        $this->register(new Rule(
            id: 'google-oauth-access-token',
            name: 'Google OAuth Access Token',
            pattern: '/(?<![A-Za-z0-9_\-])ya29\.[0-9A-Za-z\-_]{25,}(?![A-Za-z0-9_\-])/',
            severity: Severity::HIGH,
            category: 'Cloud Provider',
            description: 'Google OAuth 2.0 User Access Token'
        ));

        // 7. GitHub Personal Access Token (Classic)
        $this->register(new Rule(
            id: 'github-pat-classic',
            name: 'GitHub PAT (Classic)',
            pattern: '/(?<![A-Za-z0-9_])ghp_[0-9a-zA-Z]{36}(?![A-Za-z0-9_])/',
            severity: Severity::CRITICAL,
            category: 'VCS',
            description: 'GitHub Personal Access Token (Classic ghp_ format)'
        ));

        // 8. GitHub Fine-Grained Personal Access Token
        $this->register(new Rule(
            id: 'github-pat-fine-grained',
            name: 'GitHub Fine-Grained PAT',
            pattern: '/(?<![A-Za-z0-9_])github_pat_[0-9a-zA-Z_]{82}(?![A-Za-z0-9_])/',
            severity: Severity::CRITICAL,
            category: 'VCS',
            description: 'GitHub Fine-Grained Personal Access Token'
        ));

        // 9. GitHub OAuth Access Token
        $this->register(new Rule(
            id: 'github-oauth-token',
            name: 'GitHub OAuth Access Token',
            pattern: '/(?<![A-Za-z0-9_])gho_[0-9a-zA-Z]{36}(?![A-Za-z0-9_])/',
            severity: Severity::CRITICAL,
            category: 'VCS',
            description: 'GitHub OAuth App Access Token'
        ));

        // 10. GitHub App Token (User-to-Server / Server-to-Server)
        $this->register(new Rule(
            id: 'github-app-token',
            name: 'GitHub App Token',
            pattern: '/(?<![A-Za-z0-9_])(?:ghu|ghs)_[0-9a-zA-Z]{36}(?![A-Za-z0-9_])/',
            severity: Severity::HIGH,
            category: 'VCS',
            description: 'GitHub App Installation or User Token'
        ));

        // 11. JSON Web Token (JWT)
        $this->register(new Rule(
            id: 'jwt-token',
            name: 'JSON Web Token (JWT)',
            pattern: '/(?<![A-Za-z0-9_\-])(eyJ[A-Za-z0-9_\-]{8,}\.eyJ[A-Za-z0-9_\-]{8,}\.[A-Za-z0-9_\-]{16,})(?![A-Za-z0-9_\-])/',
            severity: Severity::MEDIUM,
            category: 'Authentication',
            description: 'RFC 7519 JSON Web Token credentials',
            matchGroup: 1
        ));

        // 12. Stripe Secret Key (Live)
        $this->register(new Rule(
            id: 'stripe-secret-key',
            name: 'Stripe Secret Key',
            pattern: '/(?<![A-Za-z0-9_])sk_live_[0-9a-zA-Z]{24,34}(?![A-Za-z0-9_])/',
            severity: Severity::CRITICAL,
            category: 'Payment',
            description: 'Stripe Live Secret API Key'
        ));

        // 13. Stripe Restricted Key (Live)
        $this->register(new Rule(
            id: 'stripe-restricted-key',
            name: 'Stripe Restricted Key',
            pattern: '/(?<![A-Za-z0-9_])rk_live_[0-9a-zA-Z]{24,34}(?![A-Za-z0-9_])/',
            severity: Severity::HIGH,
            category: 'Payment',
            description: 'Stripe Live Restricted Access Key'
        ));

        // 14. Private SSH / RSA / EC / PGP Keys
        $this->register(new Rule(
            id: 'private-ssh-key',
            name: 'Private Cryptographic Key',
            pattern: '/-----BEGIN (?:RSA |EC |OPENSSH |DSA |PGP )?PRIVATE KEY-----/',
            severity: Severity::CRITICAL,
            category: 'Cryptography',
            description: 'Unencrypted Private Cryptographic / SSH Key Header'
        ));

        // 15. Database Connection URL with Credentials
        $this->register(new Rule(
            id: 'database-connection-url',
            name: 'Database Connection URL',
            pattern: '/(?:postgres|postgresql|mysql|mongodb|redis|amqp|mssql):\/\/[^\s:@\'"]+:[^\s:@\'"]+@[^\s:@\'"]+(?::\d+)?\/[^\s\'"]+/i',
            severity: Severity::CRITICAL,
            category: 'Database',
            description: 'Database connection string containing embedded plaintext credentials'
        ));

        // 16. Slack API Token (Bot, App, User)
        $this->register(new Rule(
            id: 'slack-api-token',
            name: 'Slack API Token',
            pattern: '/(?<![A-Za-z0-9_])xox[baprs]-[0-9a-zA-Z]{10,48}(?![A-Za-z0-9_])/',
            severity: Severity::HIGH,
            category: 'Communication',
            description: 'Slack Bot or User OAuth Token'
        ));

        // 17. Slack Incoming Webhook URL
        $this->register(new Rule(
            id: 'slack-webhook-url',
            name: 'Slack Webhook URL',
            pattern: '/https:\/\/hooks\.slack\.com\/services\/T[0-9A-Za-z_]{8,11}\/B[0-9A-Za-z_]{8,11}\/[0-9A-Za-z_]{24}/',
            severity: Severity::HIGH,
            category: 'Communication',
            description: 'Slack Incoming Webhook URL with secret token payload'
        ));

        // 18. Discord Bot Token
        $this->register(new Rule(
            id: 'discord-bot-token',
            name: 'Discord Bot Token',
            pattern: '/(?<![A-Za-z0-9_\-])[MNO][A-Za-z\d_-]{23,27}\.[A-Za-z\d_-]{6}\.[A-Za-z\d_-]{27,38}(?![A-Za-z0-9_\-])/',
            severity: Severity::HIGH,
            category: 'Communication',
            description: 'Discord Bot Authentication Token'
        ));

        // 19. Discord Webhook URL
        $this->register(new Rule(
            id: 'discord-webhook-url',
            name: 'Discord Webhook URL',
            pattern: '/https:\/\/(?:ptb\.|canary\.)?discord\.com\/api\/webhooks\/\d{17,20}\/[A-Za-z0-9_-]{60,68}/',
            severity: Severity::MEDIUM,
            category: 'Communication',
            description: 'Discord Channel Incoming Webhook URL'
        ));

        // 20. Telegram Bot Token
        $this->register(new Rule(
            id: 'telegram-bot-token',
            name: 'Telegram Bot Token',
            pattern: '/(?<![0-9])[0-9]{9,10}:[a-zA-Z0-9_-]{35}(?![a-zA-Z0-9_-])/',
            severity: Severity::HIGH,
            category: 'Communication',
            description: 'Telegram Bot API Authentication Token'
        ));

        // 21. Twilio API Key / Account SID
        $this->register(new Rule(
            id: 'twilio-api-key',
            name: 'Twilio API Key / SID',
            pattern: '/(?<![A-Za-z0-9])(?:AC|SK)[a-f0-9]{32}(?![a-f0-9])/',
            severity: Severity::HIGH,
            category: 'Communication',
            description: 'Twilio Account SID or API Key'
        ));

        // 22. SendGrid API Key
        $this->register(new Rule(
            id: 'sendgrid-api-key',
            name: 'SendGrid API Key',
            pattern: '/(?<![A-Za-z0-9_\-])SG\.[a-zA-Z0-9_\-]{22}\.[a-zA-Z0-9_\-]{40,46}(?![A-Za-z0-9_\-])/',
            severity: Severity::HIGH,
            category: 'Communication',
            description: 'SendGrid Email API Key'
        ));

        // 23. Mailgun API Key
        $this->register(new Rule(
            id: 'mailgun-api-key',
            name: 'Mailgun API Key',
            pattern: '/(?<![A-Za-z0-9_\-])key-[0-9a-zA-Z]{32}(?![A-Za-z0-9_\-])/',
            severity: Severity::HIGH,
            category: 'Communication',
            description: 'Mailgun Email Service API Key'
        ));

        // 24. Square Access Token
        $this->register(new Rule(
            id: 'square-access-token',
            name: 'Square Access Token',
            pattern: '/(?<![A-Za-z0-9_\-])sq0atp-[0-9A-Za-z\-_]{22}(?![A-Za-z0-9_\-])/',
            severity: Severity::HIGH,
            category: 'Payment',
            description: 'Square Production Access Token'
        ));

        // 25. Shopify Access Token
        $this->register(new Rule(
            id: 'shopify-access-token',
            name: 'Shopify Access Token',
            pattern: '/(?<![A-Za-z0-9_])(?:shpat_|shpca_)[a-fA-F0-9]{32}(?![A-Za-z0-9_])/',
            severity: Severity::HIGH,
            category: 'E-Commerce',
            description: 'Shopify Admin or Custom App API Access Token'
        ));

        // 26. Cloudinary Credentials URL
        $this->register(new Rule(
            id: 'cloudinary-credentials',
            name: 'Cloudinary Credentials URL',
            pattern: '/cloudinary:\/\/[0-9]+:[a-zA-Z0-9_\-]+@[a-zA-Z0-9_\-]+/i',
            severity: Severity::HIGH,
            category: 'Media/Cloud',
            description: 'Cloudinary media API credentials URI'
        ));

        // 27. NPM Access Token
        $this->register(new Rule(
            id: 'npm-access-token',
            name: 'NPM Access Token',
            pattern: '/(?<![A-Za-z0-9_])npm_[A-Za-z0-9]{32,36}(?![A-Za-z0-9_])/',
            severity: Severity::HIGH,
            category: 'Package Registry',
            description: 'Node Package Manager Automation or User Token'
        ));

        // 28. PyPI API Token
        $this->register(new Rule(
            id: 'pypi-api-token',
            name: 'PyPI API Token',
            pattern: '/(?<![A-Za-z0-9_\-])pypi-AgEIcHlwaS5vcmc[A-Za-z0-9_\-]{50,}(?![A-Za-z0-9_\-])/',
            severity: Severity::HIGH,
            category: 'Package Registry',
            description: 'Python Package Index API Token'
        ));

        // 29. Generic API Key / Secret Assignment (with Shannon Entropy filter)
        $this->register(new Rule(
            id: 'generic-secret-assignment',
            name: 'Generic Secret Assignment',
            pattern: '/(?i)(?:api_key|apikey|app_secret|auth_token|client_secret|private_key)\s*[:=]\s*[\'"]([0-9a-zA-Z_\-]{16,64})[\'"]/',
            severity: Severity::MEDIUM,
            category: 'Generic',
            description: 'High-entropy assignment to variable labeled secret or api key',
            entropyThreshold: 3.5,
            matchGroup: 1
        ));

        // 30. Generic Bearer Token
        $this->register(new Rule(
            id: 'generic-bearer-token',
            name: 'Bearer Authorization Token',
            pattern: '/(?i)bearer\s+([a-zA-Z0-9_\-\.]{24,120})/',
            severity: Severity::MEDIUM,
            category: 'Generic',
            description: 'HTTP Bearer authorization token with high Shannon entropy',
            entropyThreshold: 3.8,
            matchGroup: 1
        ));
    }
}
