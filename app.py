
import streamlit as st

from analyzer.llm_analysis import analyze_all_contexts
from analyzer.pipeline import analyze_contract
from analyzer.report import generate_pdf_report


st.set_page_config(
    page_title="VulnLens",
    page_icon=None,
    layout="wide",
    initial_sidebar_state="collapsed",
)

st.markdown(
    """
    <style>
    .stApp { background: #f7f9fc; }
    .block-container {
        max-width: 1100px;
        padding-top: 2.5rem;
        padding-bottom: 4rem;
    }
    h1, h2, h3 { color: #172033; }
    .main-title {
        font-size: 2.4rem;
        font-weight: 750;
        letter-spacing: -0.03em;
        color: #172033;
        margin-bottom: 0.25rem;
    }
    .main-subtitle {
        color: #667085;
        font-size: 1rem;
        margin-bottom: 2rem;
    }
    .info-card, .report-card {
        background: #ffffff;
        border: 1px solid #dfe4ec;
        border-radius: 14px;
        padding: 1.1rem 1.25rem;
    }
    .info-card { min-height: 105px; }
    .info-label {
        color: #667085;
        font-size: 0.78rem;
        font-weight: 650;
        text-transform: uppercase;
        letter-spacing: 0.04em;
    }
    .info-value {
        color: #172033;
        font-size: 1.15rem;
        margin-top: 0.35rem;
        font-weight: 600;
        overflow-wrap: anywhere;
    }
    .report-card { margin-top: 2rem; }
    div.stButton > button {
        width: 100%;
        border-radius: 9px;
        min-height: 44px;
        font-weight: 650;
    }
    </style>
    """,
    unsafe_allow_html=True,
)

st.markdown(
    '<div class="main-title">VulnLens</div>',
    unsafe_allow_html=True,
)
st.markdown(
    '<div class="main-subtitle">'
    "Evidence-based vulnerability detection for Solidity smart contracts"
    "</div>",
    unsafe_allow_html=True,
)

uploaded_file = st.file_uploader(
    "Upload Solidity source",
    type=["sol"],
    accept_multiple_files=False,
)

if uploaded_file is None:
    st.info("Upload a Solidity (.sol) file to generate a security report.")
    st.stop()

try:
    source_code = uploaded_file.getvalue().decode("utf-8")
except UnicodeDecodeError:
    st.error("The uploaded Solidity file could not be decoded as UTF-8.")
    st.stop()

filename = uploaded_file.name
line_count = len(source_code.splitlines())
source_size_kb = len(uploaded_file.getvalue()) / 1024

st.subheader("Contract overview")
col1, col2, col3 = st.columns(3)

with col1:
    st.markdown(
        '<div class="info-card">'
        '<div class="info-label">Contract</div>'
        f'<div class="info-value">{filename}</div>'
        '</div>',
        unsafe_allow_html=True,
    )

with col2:
    st.markdown(
        '<div class="info-card">'
        '<div class="info-label">Source size</div>'
        f'<div class="info-value">{source_size_kb:.1f} KB</div>'
        '</div>',
        unsafe_allow_html=True,
    )

with col3:
    st.markdown(
        '<div class="info-card">'
        '<div class="info-label">Source lines</div>'
        f'<div class="info-value">{line_count}</div>'
        '</div>',
        unsafe_allow_html=True,
    )

with st.expander("View Solidity source"):
    st.code(source_code, language="solidity", line_numbers=True)

st.write("")

if st.button("Generate Security Report", type="primary"):
    with st.spinner("Analyzing contract and generating report..."):
        try:
            analysis = analyze_contract(filename, source_code)

            if not analysis.get("success"):
                st.error(
                    analysis.get("message", "Analysis failed.")
                )
                st.stop()

            contexts = analysis.get("llm_contexts", [])
            llm_results = analyze_all_contexts(contexts + analysis.get("informational_contexts", []))

            # Display actual LLM errors for debugging.
            failed_results = [
                result
                for result in llm_results.values()
                if isinstance(result, dict)
                and not result.get("_llm_available", False)
            ]

            if failed_results:
                st.warning(
                    "LLM contextual analysis failed for one or more "
                    "findings. Details below:"
                )
                for index, result in enumerate(failed_results, start=1):
                    st.caption(f"LLM error {index}")
                    st.code(
                        str(
                            result.get(
                                "_llm_error",
                                "No error details returned.",
                            )
                        )
                    )
            else:
                st.success("LLM contextual analysis completed.")

            pdf_bytes = generate_pdf_report(analysis, llm_results)

            st.session_state["analysis"] = analysis
            st.session_state["llm_results"] = llm_results
            st.session_state["report_pdf"] = pdf_bytes
            st.session_state["report_filename"] = (
                filename.rsplit(".", 1)[0] + "_security_report.pdf"
            )

            st.success("Security report generated successfully.")

        except Exception as exc:
            st.error("An unexpected error occurred while generating the report.")
            st.exception(exc)

if "report_pdf" in st.session_state:
    st.markdown('<div class="report-card">', unsafe_allow_html=True)
    st.subheader("Security report")
    st.markdown(
        "The report includes detected findings, evidence, relevant Solidity "
        "context, contextual reasoning, attack scenarios, and remediation "
        "guidance where available."
    )

    st.download_button(
        label="Download PDF Report",
        data=st.session_state["report_pdf"],
        file_name=st.session_state["report_filename"],
        mime="application/pdf",
        type="primary",
    )
    st.markdown("</div>", unsafe_allow_html=True)

    st.write("")
    st.pdf(
        st.session_state["report_pdf"],
        height=950,
        key="vulnlens_report_viewer",
    )
