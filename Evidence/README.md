# Evidence

These screenshots are from my local build of the platform, taken on September 13, 2026. I blacked out cloud account IDs, subscription IDs, my email address, and my username and hostname. Everything else is exactly what the app showed.

The platform has two parts. Track B is a portal where a team submits a project, it gets scanned, and it comes back rated LOW, MEDIUM or HIGH. Track A scans cloud accounts that are already running (AWS and Azure) and maps what it finds to CIS benchmarks. Both parts write to the same findings table.

## Track B: project intake and risk rating

**Submit A Project.png**
This is the intake form. You give it a repo URL or upload an archive, then answer six questions about the project: what data it handles, who can reach it, how users log in, how much damage a compromise could do, which compliance rules apply, and whether vendors can touch the data. The form won't take a partial answer. A blank answer would count as zero and make the project look safer than it is.

**Submitted Projects.png**
This is the list of projects I've run through it. The number in the "Latest submission" column is a database ID, not a count. There are 5 projects here. The IDs skip around because test submissions I made while building the app were deleted later.

**Submission 14.png**
This is the status page for a real repo, my AWS AI SOC Copilot project. It records the exact commit that was scanned, so the rating can be traced back to that code.

**Submission 65 Report.png**
Dirty Fixture is a small test repo I built on purpose to be insecure. It has a fake AWS key, old versions of `requests` and `flask` with known CVEs, a security group open to the internet, and a container that runs as root. It's there to prove the scanners catch real problems. All four scanners reported findings: Checkov 7, Trivy 14, Semgrep 3 and Gitleaks 2. It rated HIGH with a score of 77 and the gate is blocked. Two hard overrides fired: `live_secret` (the fake key) and `regulated_public` (I said it handles regulated data and is publicly reachable).

**Submission 49 Report.png** and **Submission 49 Report.pdf**
This one tests something specific. I put two files in the repo that can't be parsed. Semgrep skips a broken file and still exits successfully, so without extra handling the scan would look cleaner than it really was. The platform catches that and shows a "Scan coverage warnings (3)" box above the findings. The score is only 43, but it still rated HIGH because a secret was found, and a live secret forces HIGH no matter what the score is. The PDF is the downloadable version of the same report.

## Track A: cloud estate scanning

**Cloud Estate.png**
This shows the two cloud sources I've registered, one AWS account and one Azure subscription, with the results of their last scan. The scanner uses read-only access: an IAM role with SecurityAudit in AWS, and a service principal with the Reader role in Azure. It can't change anything in either account.

**AWS Estate.png**
The AWS scan covered 40 resources and found 9 issues. The critical one is an old security group with SSH open to the internet. The two high ones are IAM policies with wildcard permissions. The six medium ones are S3 buckets that don't require HTTPS. Every finding maps to a CIS AWS control.

**Azure Estate.png**
The Azure scan covered 8 resources and found 2 issues. The subscription doesn't export its Activity Log anywhere (CIS Azure 5.1.1), and there's an Owner role assignment at subscription scope. The Owner finding doesn't have a CIS control mapped to it, and the page says so under "Scan warnings" rather than leaving it out.

The "Risk report: rated vs. observed" section on both pages is where Tracks A and B meet. If a project was rated LOW or MEDIUM but its cloud resources turn out to be exposed, it shows up there. Both show zero right now, and that's accurate. The one exposed resource, the SSH security group, isn't part of any project I submitted.

## Tests

**Pytest.png**
The test suite passes: 120 tests. They cover the risk scoring (including the exact point where 34 is LOW and 35 is MEDIUM), the hard overrides, the CIS mapping, the read-only guard on the cloud connectors, and the scan-warning handling. The 2 warnings are deprecation notices from third-party libraries, not from my code.

## Known limitations

- Login is in development mode. There's no identity provider hooked up yet, so the sign-in form accepts any email address. It's only reachable from this machine. Setting three OIDC values turns on real sign-in.
- Submissions 7, 8, 9 and 12 show "complete" but have no rating. They were scanned before the classifier was connected to the worker. Everything scanned after that has a rating.
