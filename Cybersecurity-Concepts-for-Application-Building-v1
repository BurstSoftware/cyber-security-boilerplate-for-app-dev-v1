import streamlit as st

def main():
    # Set page configuration
    st.set_page_config(page_title="Cybersecurity Concepts for Application Building", page_icon="🔒", layout="wide")

    # Title and introduction
    st.title("🔒 Cybersecurity Concepts for Application Building")
    st.write("""
    Cybersecurity is critical when building applications to protect data, users, and systems from threats. 
    Below are the core concepts of cybersecurity as they apply to application development, with practical implementation tips.
    Click on each concept to learn more!
    """)

    # Dictionary of cybersecurity concepts and their details
    concepts = {
        "Confidentiality": {
            "description": "Ensure sensitive data is only accessible to authorized users.",
            "implementation": "Use encryption (e.g., AES-256 for data at rest, TLS for data in transit), secure authentication (e.g., OAuth 2.0), and role-based access controls (RBAC)."
        },
        "Integrity": {
            "description": "Protect data from unauthorized modification or corruption.",
            "implementation": "Use input validation to prevent injection attacks (e.g., SQL injection, XSS), secure coding practices, and hashing (e.g., SHA-256) for data integrity."
        },
        "Availability": {
            "description": "Ensure the application and data are accessible when needed.",
            "implementation": "Mitigate DoS attacks with rate limiting, load balancing, and redundancy. Implement regular backups and disaster recovery plans."
        },
        "Authentication": {
            "description": "Verify the identity of users or systems accessing the application.",
            "implementation": "Use strong password policies, multi-factor authentication (MFA), and secure session management (e.g., short-lived JWT tokens)."
        },
        "Authorization": {
            "description": "Control what authenticated users or systems can do.",
            "implementation": "Implement least privilege principles, role-based access control (RBAC), and attribute-based access control (ABAC)."
        },
        "Secure Development Lifecycle (SDL)": {
            "description": "Integrate security at every stage of development.",
            "implementation": "Follow OWASP Secure Coding Practices, perform code reviews, and use static/dynamic analysis tools (e.g., SonarQube, OWASP ZAP)."
        },
        "Input Validation and Sanitization": {
            "description": "Prevent malicious inputs from compromising the application.",
            "implementation": "Validate and sanitize all user inputs, use parameterized queries for databases, and escape outputs to prevent XSS."
        },
        "Secure APIs": {
            "description": "Protect APIs from unauthorized access or abuse.",
            "implementation": "Use API keys, OAuth, rate limiting, and input validation. Follow OWASP API Security Top 10 guidelines."
        },
        "Data Protection": {
            "description": "Safeguard sensitive data throughout its lifecycle.",
            "implementation": "Encrypt sensitive data, anonymize or mask data, and comply with regulations (e.g., GDPR, CCPA)."
        },
        "Logging and Monitoring": {
            "description": "Detect and respond to security incidents in real-time.",
            "implementation": "Log security-relevant events, use intrusion detection systems, and monitor for anomalies."
        },
        "Patch Management": {
            "description": "Keep software and dependencies updated to address vulnerabilities.",
            "implementation": "Regularly update dependencies (e.g., using Dependabot) and apply security patches promptly."
        },
        "Secure Configuration": {
            "description": "Harden the application and its environment to reduce attack surfaces.",
            "implementation": "Disable unnecessary features, use secure defaults, and configure servers securely (e.g., disable directory listing)."
        },
        "Threat Modeling": {
            "description": "Identify and prioritize potential threats during design.",
            "implementation": "Use frameworks like STRIDE to assess risks and design mitigations early."
        },
        "Error Handling": {
            "description": "Prevent sensitive information leakage through errors.",
            "implementation": "Avoid exposing stack traces or database details in error messages and use generic error responses."
        },
        "Secure Deployment": {
            "description": "Ensure the application remains secure in production.",
            "implementation": "Use secure CI/CD pipelines, container security (e.g., Docker scanning), and infrastructure-as-code with security checks."
        }
    }

    # Create two columns for better layout
    col1, col2 = st.columns(2)

    # Split concepts between two columns for balanced display
    concept_keys = list(concepts.keys())
    mid_point = len(concept_keys) // 2

    # Column 1
    with col1:
        for concept in concept_keys[:mid_point]:
            with st.expander(f"**{concept}**"):
                st.write(f"**Description**: {concepts[concept]['description']}")
                st.write(f"**Implementation**: {concepts[concept]['implementation']}")

    # Column 2
    with col2:
        for concept in concept_keys[mid_point:]:
            with st.expander(f"**{concept}**"):
                st.write(f"**Description**: {concepts[concept]['description']}")
                st.write(f"**Implementation**: {concepts[concept]['implementation']}")

    # Additional resources section
    st.header("📚 Additional Resources")
    st.write("""
    - [OWASP Top Ten](https://owasp.org/www-project-top-ten/): Common application security risks.
    - [NIST SP 800-53](https://csrc.nist.gov/publications/detail/sp/800-53/rev-5/final): Security and privacy controls.
    - [OWASP Secure Coding Practices](https://owasp.org/www-project-secure-coding-practices-quick-reference-guide/): Guidelines for secure coding.
    """)

    # Footer
    st.markdown("---")
    st.write("Built with Streamlit | Cybersecurity Concepts for Application Development | © 2025")

if __name__ == "__main__":
    main()
