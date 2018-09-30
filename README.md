# Malware Analysis

**Examining Document Files**

Microsft Office Documents 
* **officeparser**: [https://github.com/unixfreak0037/officeparser](https://github.com/unixfreak0037/officeparser) - parses the format of OLE compound documents used by Microsoft Office applications to extract macros or embedded files. (Python)
* **oletools**: [http://www.decalage.info/python/oletools](http://www.decalage.info/python/oletools) - a package of tools for analyzing Microsoft OLE2 files. (Python)
* **oledump.py**: [https://blog.didierstevens.com/programs/oledump-py/](https://blog.didierstevens.com/programs/oledump-py/) - tool developed by Didier Stevens for analyzing streams within ole files. (Python)

PDFs
* **pdfid**: https://blog.didierstevens.com/programs/pdf-tools/](https://blog.didierstevens.com/programs/pdf-tools/) - scan a file to look for certain PDF keywords, allowing you to identify PDF documents that contain (for example) JavaScript or execute an action when opened. 
* **pdf-parser.py**: https://blog.didierstevens.com/programs/pdf-tools/](https://blog.didierstevens.com/programs/pdf-tools/) -  parse a PDF document to identify the fundamental elements used in the analyzed file. 
**String Analysis**

* **FLOSS**: [https://github.com/fireeye/flare-floss](https://github.com/fireeye/flare-floss) - uses advanced static analysis techniques to automatically deobfuscate strings from malware binaries
* **CyberChef**: [https://gchq.github.io/CyberChef](https://gchq.github.io/CyberChef) - Decode and identify a variety of data formats

**.NET Reversing and debugging**
* **dnSpy**: [https://github.com/0xd4d/dnSpy](https://github.com/0xd4d/dnSpy) - tool for debugging and editing .NET assemblies when no source code is available

**Android/Java**
* **dex2jar**: [https://github.com/pxb1988/dex2jar](https://github.com/pxb1988/dex2jar) - convert dex files to .class files
* **JD-GUI**: [http://jd.benow.ca/](http://jd.benow.ca/) - utility for viewing java source code .class files
* **Evil-Droid**: [https://github.com/M4sc3r4n0/Evil-Droid](https://github.com/M4sc3r4n0/Evil-Droid) - framework to create, generate & embed apk payloads to penetrate android platforms

# Threat Hunting

**Hypothesis Generation**

* **Mitre ATT&CK** [https://attack.mitre.org/wiki/Main_Page](https://attack.mitre.org/wiki/Main_Page)
* **Unfetter** [https://nsacyber.github.io/unfetter/](https://nsacyber.github.io/unfetter/)

**Hunting Overviews**

* **Sqrrl Practical Guide** [https://sqrrl.com/media/ebook-web.pdf](https://sqrrl.com/media/ebook-web.pdf) - Your practical guide to threathunting 

# Cloud Tools
Forked from toniblyx/my-arsenal-of-aws-security-tools

**Identify and Protect**

* **Scout2**: [https://github.com/nccgroup/Scout2](https://github.com/nccgroup/Scout2) - Security auditing tool for AWS environments (Python)
* **Prowler**: [https://github.com/toniblyx/prowler](https://github.com/toniblyx/prowler) - CIS benchmarks and additional checks for security best practices in AWS (Shell Script)
* **CloudSploit**: [https://github.com/cloudsploit/scans](https://github.com/cloudsploit/scans) - AWS security scanning checks (NodeJS)
* **CloudMapper**: [https://github.com/duo-labs/cloudmapper](https://github.com/duo-labs/cloudmapper) - visualize components of your AWS environment
* **CloudTracker**: [https://github.com/duo-labs/cloudtracker](https://github.com/duo-labs/cloudtracker) - helps you find over-privileged IAM users and roles by comparing CloudTrail logs with current IAM policies (Python)
* **AWS Security Benchmarks**: [https://github.com/awslabs/aws-security-benchmark](https://github.com/awslabs/aws-security-benchmark) - scrips and templates guidance related to the AWS CIS Foundation framework (Python)
* **AWS Public IPs**: [https://github.com/arkadiyt/aws_public_ips](https://github.com/arkadiyt/aws_public_ips) - Fetch all public IP addresses tied to your AWS account. Works with IPv4/IPv6, Classic/VPC networking, and across all AWS services (Ruby)
* **PMapper**: [https://github.com/nccgroup/PMapper](https://github.com/nccgroup/PMapper) - Advanced and Automated AWS IAM Evaluation (Python)
* **AWS-Inventory**: [https://github.com/nccgroup/aws-inventory](https://github.com/nccgroup/aws-inventory) - Make a inventory of all your resources across regions (Python)
* **Resource Counter**: [https://github.com/disruptops/resource-counter](https://github.com/disruptops/resource-counter) - Counts number of resources in categories across regions
* **ICE**: [https://github.com/Teevity/ice](https://github.com/Teevity/ice) - Ice provides insights from a usage and cost perspective, with high detail dashboards.
* **SkyArk**: [https://github.com/cyberark/SkyArk](https://github.com/cyberark/SkyArk) - SkyArk provides advanced discovery and security assessment for the most privileged entities in the tested AWS. 
* **Trailblazer AWS**: [https://github.com/willbengtson/trailblazer-aws](https://github.com/willbengtson/trailblazer-aws) - Trailblazer AWS, determine what AWS API calls are logged by CloudTrail and what they are logged as. You can also use TrailBlazer as an attack simulation framework.
* **Lunar**: [https://github.com/lateralblast/lunar](https://github.com/lateralblast/lunar) - Security auditing tool based on several security frameworks (it does some AWS checks)
* **Cloud-reports**: [https://github.com/tensult/cloud-reports](https://github.com/tensult/cloud-reports) - Scans your AWS cloud resources and generates reports
* **Amazon Macie**: [https://aws.amazon.com/macie/] (https://aws.amazon.com/macie/) - an Amazon security service that uses machine learning to automatically discover, classify, and protect sensitive data in AWS. (PAID)

**Respond:**

* **AWS IR**: [https://github.com/ThreatResponse/aws_ir](https://github.com/ThreatResponse/aws_ir) - AWS specific Incident Response and Forensics Tool
* **Margaritashotgun**: [https://github.com/ThreatResponse/margaritashotgun](https://github.com/ThreatResponse/margaritashotgun) - Linux memory remote acquisition tool
* **LiMEaide**: [https://kd8bny.github.io/LiMEaide/](https://kd8bny.github.io/LiMEaide/) - Linux memory remote acquisition tool
* **Diffy**: [https://github.com/Netflix-Skunkworks/diffy](https://github.com/Netflix-Skunkworks/diffy) - Triage tool used during cloud-centric security incidents
* **AWS Security Automation**: [https://github.com/awslabs/aws-security-automation](https://github.com/awslabs/aws-security-automation) - AWS scripts and resources for DevSecOps and automated incident response
* **GDPatrol**: [https://github.com/ansorren/GDPatrol](https://github.com/ansorren/GDPatrol) - Automated Incident Response based off AWS GuardDuty findings
* **jq**: [https://stedolan.github.io/jq/](https://stedolan.github.io/jq/)- commandline json processor, useful for parsing CloudTrail logs

**Offensive:**

* **weirdALL**: [https://github.com/carnal0wnage/weirdAAL](https://github.com/carnal0wnage/weirdAAL) - AWS Attack Library
* **Pacu**: [https://github.com/RhinoSecurityLabs/pacu](https://github.com/RhinoSecurityLabs/pacu) - AWS penetration testing toolkit
* **Cred Scanner**: [https://github.com/disruptops/cred_scanner](https://github.com/disruptops/cred_scanner)
* **AWS PWN**: [https://github.com/dagrz/aws_pwn](https://github.com/dagrz/aws_pwn)
* **Cloudfrunt**: [https://github.com/MindPointGroup/cloudfrunt](https://github.com/MindPointGroup/cloudfrunt)
* **Cloudjack**: [https://github.com/prevade/cloudjack](https://github.com/prevade/cloudjack)
* **Nimbostratus**: [https://github.com/andresriancho/nimbostratus](https://github.com/andresriancho/nimbostratus)
* **GitLeaks**: [https://github.com/zricethezav/gitleaks](https://github.com/zricethezav/gitleaks) - Audit git repos for secrets
* **TruffleHog**: [https://github.com/dxa4481/truffleHog](https://github.com/dxa4481/truffleHog) - Searches through git repositories for high entropy strings and secrets, digging deep into commit history

**Resources**

* **AWS Security Best Practices**:[https://d0.awsstatic.com/whitepapers/Security/AWS_Security_Best_Practices.pdf](https://d0.awsstatic.com/whitepapers/Security/AWS_Security_Best_Practices.pdf)

**Training:**

* [http://flaws.cloud/](http://flaws.cloud/)
* [https://github.com/RhinoSecurityLabs/cloudgoat](https://github.com/RhinoSecurityLabs/cloudgoat)
