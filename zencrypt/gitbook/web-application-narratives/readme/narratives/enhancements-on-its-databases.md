---
icon: database
description: 'Artifact Description:'
cover: ../../../.gitbook/assets/image (2).png
coverY: -134.07407407407408
layout:
  cover:
    visible: true
    size: full
  title:
    visible: true
  description:
    visible: true
  tableOfContents:
    visible: true
  outline:
    visible: true
  pagination:
    visible: true
---

# Enhancements on its Databases

Zencrypt started as a simple CLI cipher tool that I created back in August 2022. Since then, I have been able to transform it into something I'm truly proud of to be able to showcase my skills in computer science. I turned the one script CLI into a Flask web app with SQLite integration that runs on an AWS EC2. The current release, v6.2-alpha shows just how far I have taken the cipher and used different forms of cryptography in order to be able to create a tool that not just I would use, but I tailored it out for everyday use towards for other people with similar niche interests in encryption and anonymity.

Justification and Improvements:

I chose to focus on database improvements since my skills in data management are currently not as fluent as I would like them to be, especially in terms of having the code production ready for an online instance instead of a local instance. The merger from MongoDB to SQLite taught me the value of direct data control.

I moved the entire data layer to SQLite with Flask-SQLAlchemy. This was difficult because the Flask framework by nature had its own set of rules about how it approached secret variables. None the less, I set up a secure key storage system in an EC2 instance under the subdirectory “\~/etc/secrets/.” It’s also important to note that Replit, Render, and a lot of other easy hosting platform services had yet their own formal set of rules and approaches to secrets and how they handled variables and specific subdirectories. In the end, for the ability to have the control that I want for zencrypt's webapp, I chose to deploy everything to AWS EC2. The rules are whatever I want to be for my environment variables along with where and how to store user data, without being forced to subscribe to get the functionality from, for example, Renders ability to run ssh/ shell or database files.

* • MIGRATED FROM MONGODB TO SQLITE FOR BETTER CONTROL OVER DATA STRUCTURE AND USER EXPERIENCE.
* IMPLEMENTATION OF SECURE KEY STORAGE IN /ETC/SECRETS/...
* INTEGRATED WITH AWS EC2 FOR MORE CONTROL AND FUNCTIONALITY WITHIN THE DEPLOYMENT AND POST-DEPLOYMENT.
* OPTIMIZED THE DATABASE CONNECTIONS FOR THE PRODUCTION ENVIRONMENT.

#### Course Outcomes:

The database enhancement exceeded my initial goals. I learned to create solid user authentication, handle encrypted data storage, and set up a production-ready environment on AWS EC2.

#### Learning and Challenges:

Working through this merge and enhancement, none the less, was absolutely not very easy for me at all, nor was it anything I was fairly used to. Setting up /etc/secrets/ on AWS took some time to get right, and the MongoDB to SQLite migration had its moments. I noticed that managing environment variables in production needs a different approach and more attention to specific details. With that being said, moving to AWS EC2 with SQLite so far has been successful post deployment because the setup is much more effective than the last version on Render, thus giving me more control over the infrastructure while still maintaining security standards.

<figure><img src="../../../.gitbook/assets/image (2).png" alt=""><figcaption><p>Webapp</p></figcaption></figure>

<figure><img src="../../../.gitbook/assets/image (3).png" alt=""><figcaption><p>EC2 Instance</p></figcaption></figure>
