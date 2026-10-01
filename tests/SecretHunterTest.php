<?php

declare(strict_types=1);

namespace EidCloud\SecretHunter\Tests;

use EidCloud\SecretHunter\Entropy\ShannonEntropy;
use EidCloud\SecretHunter\Models\Finding;
use EidCloud\SecretHunter\Models\ScanResult;
use EidCloud\SecretHunter\Report\JsonReporter;
use EidCloud\SecretHunter\Rules\RuleRegistry;
use EidCloud\SecretHunter\Rules\Severity;
use EidCloud\SecretHunter\Scanner;

class SecretHunterTest
{
    private Scanner $scanner;
    private RuleRegistry $registry;

    public function __construct()
    {
        $this->registry = RuleRegistry::create();
        $this->scanner = new Scanner($this->registry);
    }

    public function testRuleCount(): void
    {
        $count = $this->registry->count();
        self::assert($count >= 25, "Expected at least 25 registered rules, found {$count}");
    }

    public function testOpenAiKeyDetection(): void
    {
        $sample = 'const OPENAI = "' . implode('', ['s', 'k', '-', 'p', 'r', 'o', 'j', '-']) . str_repeat('X', 45) . '";';
        $findings = $this->scanner->scanString($sample);

        self::assert(!empty($findings), "Failed to detect OpenAI project key");
        self::assert($findings[0]->ruleId === 'openai-api-key', "Expected openai-api-key, got {$findings[0]->ruleId}");
        self::assert($findings[0]->severity === Severity::CRITICAL, "Expected critical severity");
    }

    public function testAnthropicKeyDetection(): void
    {
        $sample = 'ANTHROPIC_API_KEY=' . base64_decode('c2stYW50LWFwaTAzLWFiY2RlZmdoaWprbG1ub3BxcnN0dXZ3eHl6QUJDREVGR0hJSktMTU5PUFFSU1RVVldYWVoxMjM0NTY3ODkwYWJjZGVmZ2hpamtsbW5vcHFyc3R1dnd4eXpBQg==');
        $findings = $this->scanner->scanString($sample);

        self::assert(!empty($findings), "Failed to detect Anthropic API key");
        self::assert($findings[0]->ruleId === 'anthropic-api-key', "Expected anthropic-api-key");
    }

    public function testAwsAccessKeyDetection(): void
    {
        $sample = 'aws_key = "' . implode('', ['A', 'K', 'I', 'A']) . str_repeat('9', 16) . '";';
        $findings = $this->scanner->scanString($sample);

        self::assert(!empty($findings), "Failed to detect AWS Access Key ID");
        self::assert($findings[0]->ruleId === 'aws-access-key-id', "Expected aws-access-key-id");
        self::assert($findings[0]->severity === Severity::CRITICAL);
    }

    public function testAwsSecretKeyDetection(): void
    {
        $sample = 'aws_secret_access_key = "' . base64_decode('d0phbHJYVXRuRkVNSS9LN01ERU5HL2JQeFJmaUNZRVhBTVBMRUtFWQ==') . '";';
        $findings = $this->scanner->scanString($sample);

        self::assert(!empty($findings), "Failed to detect AWS Secret Key");
        self::assert($findings[0]->ruleId === 'aws-secret-access-key', "Expected aws-secret-access-key");
    }

    public function testGoogleApiKeyDetection(): void
    {
        $sample = 'const gmap = "' . implode('', ['A', 'I', 'z', 'a']) . str_repeat('X', 35) . '";';
        $findings = $this->scanner->scanString($sample);

        self::assert(!empty($findings), "Failed to detect Google Cloud API key");
        self::assert($findings[0]->ruleId === 'google-cloud-api-key', "Expected google-cloud-api-key");
    }

    public function testGitHubPatClassicDetection(): void
    {
        $sample = 'GITHUB_TOKEN=' . base64_decode('Z2hwX0FCQ0RFRkdISUpLTE1OT1BRUlNUVVZXWFlaMTIzNDU2Nzg5MA==');
        $findings = $this->scanner->scanString($sample);

        self::assert(!empty($findings), "Failed to detect GitHub classic PAT");
        self::assert($findings[0]->ruleId === 'github-pat-classic');
    }

    public function testGitHubPatFineGrainedDetection(): void
    {
        $token = implode('', ['g', 'i', 't', 'h', 'u', 'b', '_', 'p', 'a', 't', '_']) . str_repeat('A', 82);
        $sample = "git_token = '{$token}';";
        $findings = $this->scanner->scanString($sample);

        self::assert(!empty($findings), "Failed to detect GitHub fine-grained PAT");
        self::assert($findings[0]->ruleId === 'github-pat-fine-grained');
    }

    public function testJwtTokenDetection(): void
    {
        $jwt = base64_decode('ZXlKaGJHY2lPaUpJVXpJMU5pSXNJblI1Y0NJNklrcFhWQ0o5') . '.' .
               base64_decode('ZXlKemRXSWlPaUl4TWpNMk56a3dJandpYm1GdFpTSTZJa3B2YUc0Z1JHOWxJaXdpYVdGMElqb3hOVFkyTWpNNU1ESXlmUQ==') . '.' .
               'SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c';
        $sample = "Bearer {$jwt}";
        $findings = $this->scanner->scanString($sample);

        self::assert(!empty($findings), "Failed to detect JWT token");
        $hasJwt = false;
        foreach ($findings as $f) {
            if ($f->ruleId === 'jwt-token') {
                $hasJwt = true;
                break;
            }
        }
        self::assert($hasJwt, "Expected jwt-token finding");
    }

    public function testStripeSecretKeyDetection(): void
    {
        $sample = '$stripe = new \Stripe\StripeClient("' . base64_decode('c2tfbGl2ZV81MUFiQ2RFZkdoSWpLbE1uT3BRclN0VXZXeFl6MTIzNDU2') . '");';
        $findings = $this->scanner->scanString($sample);

        self::assert(!empty($findings), "Failed to detect Stripe live key");
        self::assert($findings[0]->ruleId === 'stripe-secret-key');
    }

    public function testPrivateSshKeyDetection(): void
    {
        $sample = "-----BEGIN RSA PRIVATE KEY-----\nMIIEowIBAAKCAQEA0...\n-----END RSA PRIVATE KEY-----";
        $findings = $this->scanner->scanString($sample);

        self::assert(!empty($findings), "Failed to detect RSA Private Key");
        self::assert($findings[0]->ruleId === 'private-ssh-key');
    }

    public function testDatabaseUrlDetection(): void
    {
        $sample = 'DATABASE_URL="postgres://admin:super_secret_pwd_123@db.prod.internal:5432/main_db"';
        $findings = $this->scanner->scanString($sample);

        self::assert(!empty($findings), "Failed to detect Database URL");
        self::assert($findings[0]->ruleId === 'database-connection-url');
    }

    public function testSlackTokenDetection(): void
    {
        $sample = 'slack_token = "' . base64_decode('eG94Yi0xMjM0NTY3ODkwMTItMTIzNDU2Nzg5MDEyMy1hYmNkZWZnaGlqa2xtbm9wcXJzdHV2d3g=') . '";';
        $findings = $this->scanner->scanString($sample);

        self::assert(!empty($findings), "Failed to detect Slack token");
        self::assert($findings[0]->ruleId === 'slack-api-token');
    }

    public function testSlackWebhookDetection(): void
    {
        $sample = 'curl -X POST ' . base64_decode('aHR0cHM6Ly9ob29rcy5zbGFjay5jb20vc2VydmljZXMvVDAwMDAwMDAwL0IwMDAwMDAwMC9YWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFg=');
        $findings = $this->scanner->scanString($sample);

        self::assert(!empty($findings), "Failed to detect Slack webhook");
        self::assert($findings[0]->ruleId === 'slack-webhook-url');
    }

    public function testTelegramBotTokenDetection(): void
    {
        $sample = 'TELEGRAM_BOT_TOKEN="' . base64_decode('MTIzNDU2Nzg5MDpBQkNkZWZHSElqa2xNTk9wcXJzVFVWd3h5ejEyMzQ1Njc4OQ==') . '"';
        $findings = $this->scanner->scanString($sample);

        self::assert(!empty($findings), "Failed to detect Telegram Bot token");
        self::assert($findings[0]->ruleId === 'telegram-bot-token');
    }

    public function testSendGridKeyDetection(): void
    {
        $sample = 'SENDGRID_API_KEY="' . base64_decode('U0cuMTIzNDU2Nzg5MGFiY2RlZjEyMzQ1Ni4xMjM0NTY3ODkwYWJjZGVmZ2hpamtsbW5vcHFyc3R1dnd4eXoxMjM0NTY3ODk=') . '"';
        $findings = $this->scanner->scanString($sample);

        self::assert(!empty($findings), "Failed to detect SendGrid API key");
        self::assert($findings[0]->ruleId === 'sendgrid-api-key');
    }

    public function testDiscordBotTokenDetection(): void
    {
        $sample = 'DISCORD_TOKEN="' . base64_decode('T1RrNU9UazVPVGs1T1RrNU9UazVPVGs1LkFCQ0RFRi5hYmNkZWZnaGlqa2xtbm9wcXJzdHV2d3h5ejEyMzQ1') . '"';
        $findings = $this->scanner->scanString($sample);

        self::assert(!empty($findings), "Failed to detect Discord Bot token");
        self::assert($findings[0]->ruleId === 'discord-bot-token');
    }

    public function testShopifyTokenDetection(): void
    {
        $sample = 'shopify_key = "' . base64_decode('c2hwYXRfMTIzNDU2Nzg5MGFiY2RlZjEyMzQ1Njc4OTBhYmNkZWY=') . '";';
        $findings = $this->scanner->scanString($sample);

        self::assert(!empty($findings), "Failed to detect Shopify token");
        self::assert($findings[0]->ruleId === 'shopify-access-token');
    }

    public function testSquareTokenDetection(): void
    {
        $sample = 'square_token = "' . base64_decode('c3EwYXRwLTEyMzQ1Njc4OTAxMjM0NTY3ODkwMTI=') . '";';
        $findings = $this->scanner->scanString($sample);

        self::assert(!empty($findings), "Failed to detect Square token");
        self::assert($findings[0]->ruleId === 'square-access-token');
    }

    public function testMailgunKeyDetection(): void
    {
        $sample = 'mailgun = "' . base64_decode('a2V5LTEyMzQ1Njc4OTBhYmNkZWYxMjM0NTY3ODkwYWJjZGVm') . '";';
        $findings = $this->scanner->scanString($sample);

        self::assert(!empty($findings), "Failed to detect Mailgun key");
        self::assert($findings[0]->ruleId === 'mailgun-api-key');
    }

    public function testNpmTokenDetection(): void
    {
        $sample = 'NPM_TOKEN=' . base64_decode('bnBtXzEyMzQ1Njc4OTBBQkNERUZHSElKS0xNTk9QUVJTVFVW');
        $findings = $this->scanner->scanString($sample);

        self::assert(!empty($findings), "Failed to detect NPM token");
        self::assert($findings[0]->ruleId === 'npm-access-token');
    }

    public function testPyPiTokenDetection(): void
    {
        $sample = 'pypi_token = "' . base64_decode('cHlwaS1BZ0VJY0hsd2FTNXZjbWMxMjM0NTY3ODkwYWJjZGVmZ2hpamtsbW5vcHFyc3R1dnd4eXoxMjM0NTY3ODkwYWJjZGVm') . '";';
        $findings = $this->scanner->scanString($sample);

        self::assert(!empty($findings), "Failed to detect PyPI token");
        self::assert($findings[0]->ruleId === 'pypi-api-token');
    }

    public function testCloudinaryDetection(): void
    {
        $sample = 'CLOUDINARY_URL=cloudinary://123456789012345:abcdefghijklmnopqrstuvw_xyz@cloudname';
        $findings = $this->scanner->scanString($sample);

        self::assert(!empty($findings), "Failed to detect Cloudinary URL");
        self::assert($findings[0]->ruleId === 'cloudinary-credentials');
    }

    public function testGenericSecretAssignmentDetection(): void
    {
        // High entropy secret assignment
        $sample = 'client_secret = "8f93b5a192c4e7d0f1a2b3c4d5e6f7a8";';
        $findings = $this->scanner->scanString($sample);

        self::assert(!empty($findings), "Failed to detect Generic Secret Assignment");
        self::assert($findings[0]->ruleId === 'generic-secret-assignment');
    }

    public function testShannonEntropyCalculation(): void
    {
        // Purely homogeneous string has 0.0 entropy
        $zeroEntropy = ShannonEntropy::calculate('aaaaaaaaaaaa');
        self::assert($zeroEntropy === 0.0, "Expected 0.0 entropy for repeated character, got {$zeroEntropy}");

        // Random cryptographic string has high entropy (> 4.0)
        $cryptoKey = 'd41d8cd98f00b204e9800998ecf8427e';
        $cryptoEntropy = ShannonEntropy::calculate($cryptoKey);
        self::assert($cryptoEntropy > 3.0, "Expected hex entropy > 3.0, got {$cryptoEntropy}");

        // High entropy base64 token
        $b64Token = 'c29tZSByYW5kb20gc2VjcmV0IHRva2VuIGZvciBhdXRoZW50aWNhdGlvbg==';
        self::assert(ShannonEntropy::isHighEntropy($b64Token, 3.5), "Expected high entropy for base64 token");

        // English natural text has lower entropy
        $naturalText = 'the quick brown fox jumps over the lazy dog';
        $naturalEntropy = ShannonEntropy::calculate($naturalText);
        self::assert($naturalEntropy < 4.5, "Expected natural language entropy < 4.5, got {$naturalEntropy}");
    }

    public function testSecretMasking(): void
    {
        // OpenAI Key masking
        $openAiKey = 'sk-proj-1234567890abcdef1234567890abcdef12345678';
        $maskedOpenAi = Finding::maskSecret($openAiKey);
        self::assert(str_starts_with($maskedOpenAi, 'sk-proj-****'), "Expected prefix preserved in {$maskedOpenAi}");
        self::assert(str_ends_with($maskedOpenAi, '5678'), "Expected suffix preserved in {$maskedOpenAi}");
        self::assert(!str_contains($maskedOpenAi, '1234567890abcdef'), "Secret body must not be leaked");

        // GitHub Token masking
        $githubToken = 'ghp_1234567890ABCDEFGHIJKLMNOPQRSTUV';
        $maskedGh = Finding::maskSecret($githubToken);
        self::assert(str_starts_with($maskedGh, 'ghp_****'), "Expected ghp_ prefix preserved");

        // Generic Key masking
        $generic = 'SuperSecretCryptographicPassword12345';
        $maskedGen = Finding::maskSecret($generic);
        self::assert(str_starts_with($maskedGen, 'Supe'), "Expected first 4 chars");
        self::assert(str_ends_with($maskedGen, '2345'), "Expected last 4 chars");
        self::assert(str_contains($maskedGen, '****'));
    }

    public function testInlineIgnoreDirective(): void
    {
        // A line with an ignore tag should be skipped
        $sample = 'const API = "sk-proj-ABCDefgh1234567890abcdef1234567890abcdef12345678"; // eidcloud:ignore';
        $findings = $this->scanner->scanString($sample);
        self::assert(empty($findings), "Expected inline ignore comment to suppress finding");

        $sample2 = 'const API = "sk-proj-ABCDefgh1234567890abcdef1234567890abcdef12345678"; // nosecret';
        $findings2 = $this->scanner->scanString($sample2);
        self::assert(empty($findings2), "Expected nosecret comment to suppress finding");
    }

    public function testSeverityFiltering(): void
    {
        self::assert(Severity::isAtLeast(Severity::CRITICAL, Severity::HIGH));
        self::assert(Severity::isAtLeast(Severity::HIGH, Severity::HIGH));
        self::assert(!Severity::isAtLeast(Severity::LOW, Severity::HIGH));

        $result = new ScanResult();
        $result->addFinding(new Finding('rule-1', 'Test', Severity::LOW, 'Gen', 'f.php', 1, 1, 'sec1'));
        $result->addFinding(new Finding('rule-2', 'Test', Severity::CRITICAL, 'Gen', 'f.php', 2, 1, 'sec2'));

        self::assert($result->hasCriticalOrHigh() === true);
        self::assert(count($result->getFilteredFindings(Severity::HIGH)) === 1);
        self::assert(count($result->getFilteredFindings(Severity::LOW)) === 2);
    }

    public function testJsonReporterOutput(): void
    {
        $result = new ScanResult([], '/test/path');
        $result->addFinding(new Finding(
            ruleId: 'openai-api-key',
            ruleName: 'OpenAI API Key',
            severity: Severity::CRITICAL,
            category: 'AI/ML',
            file: 'config.php',
            line: 12,
            column: 5,
            rawSecret: 'sk-proj-1234567890abcdef1234567890abcdef12345678',
            snippet: 'key = "sk-proj-..."'
        ));

        $jsonStr = JsonReporter::render($result, true);
        $decoded = json_decode($jsonStr, true);

        self::assert(is_array($decoded), "JSON output failed to parse");
        self::assert(isset($decoded['summary']), "Missing summary in JSON");
        self::assert(isset($decoded['findings']), "Missing findings in JSON");
        self::assert($decoded['summary']['total_secrets'] === 1);
        self::assert(str_starts_with($decoded['findings'][0]['secret'], 'sk-proj-****'));
    }

    private static function assert(bool $condition, string $message = 'Assertion failed'): void
    {
        if (!$condition) {
            throw new \AssertionError($message);
        }
    }
}
