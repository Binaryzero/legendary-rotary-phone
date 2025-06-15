#!/usr/bin/env python3
"""
Minimal Streamlit app to test basic functionality.
"""

import streamlit as st

def main():
    st.title("Test App")
    st.write("If you can see this, basic Streamlit works")
    
    name = st.text_input("Enter your name:")
    if st.button("Submit"):
        st.write(f"Hello {name}")

if __name__ == "__main__":
    main()