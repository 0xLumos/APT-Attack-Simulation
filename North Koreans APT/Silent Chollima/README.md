# Silent Chollima APT Adversary Simulation

This is a simulation of attack by (Silent Chollima) APT group targeting several customers and their users in North America, Asia, and Europe. The attack campaign was active in June 2025, have sent a link leading to a ZIP or RAR archive file. Inside this file would be a legitimate executable that was given a filename relevant to the targeted organization or tied to the theme of the spear phish email.When executed, this legitimate executable would load a malicious payload in an included Dynamic Link Library (DLL), via search order hijacking which provided operators with the ability to remotely execute commands on infected devices. I relied on volexity to figure out the details to make this: https://www.volexity.com/blog/2025/10/08/apt-meets-gpt-targeted-operations-with-untamed-llms/

![1623606708028](https://github.com/user-attachments/assets/7d4cc2c8-fce1-4e7c-b276-2a7bed69248f)

1. Social engineering technique: The attackers sent phishing emails containing HTML that included an image to make it appear a document was attached to the email. If the image were clicked, it led to the download of a remotely hosted archive file.

2. GOVERSHELL: All implants were DLL files that were loaded via search order hijacking from the legitimate version of either the 32- or 64-bit version of an open-source project.

3. Persistence & C2 traffic: Each variant of GOVERSHELL sets up persistence via a scheduled task on its first execution and includes a command-line flag in that persistence execution, which is required to execute the logic that includes C2 communication.

<img width="938" height="289" alt="imageedit_1_9709470955" src="https://github.com/user-attachments/assets/69920aa9-ecc3-48d6-823a-06e26ef433e7" />



## The first stage (social engineering technique)

Silent Chollima primary and sole method for targeting organizations is by conducting spear phishing campaigns. Between June and August 2025, Silent Chollima sent phishing emails containing HTML that included an image to make it appear a document was attached to the email. If the image were clicked, it led to the download of a remotely hosted archive file. Users would then need to open and execute the executable file within the archive in order to become infected. An example body from one such email is included below.


<img width="606" height="403" alt="imageedit_3_3905276592" src="https://github.com/user-attachments/assets/2de80e43-4933-421d-bb61-c34281e6bc5e" />



