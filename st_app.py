## build a streamlit app to show all the results

# Path: edge-iiot/st_app.py
import io
import pandas as pd
import dill
import streamlit as st
from  helper import plot_confusion_matrix,plot_confusion_matrix,plot_precision_recall_curve,compute_metrics, data_type

trained_model = dill.load(open(r'C:/Users/liush/Downloads/model.dill', 'rb'))

# @st.cache_data(experimental_allow_widgets=True) 
def main():
    
    ## write a front end view for the app
    html_temp = """
    <div style="background-color:tomato;padding:10px">
    <h2 style="color:white;text-align:center;">CyberSecurity Detector!</h2>
    </div>
    """
    ## display the front end aspect
    st.markdown(html_temp,unsafe_allow_html=True)
    
    st.write('This is a simple app to show the results of the predictive maintenance model.')
    
    file = st.file_uploader("Upload file", type=["csv"])
    if file is not None:
        try:
            ## read the uploaded csv file
            
            df = pd.read_csv(file, low_memory=False, dtype=data_type)
            X,y = df.drop(columns=['Attack_label','Attack_type']), df['Attack_label']
            st.subheader('Data')
            st.write(df.head())
        except Exception as e:
            st.write(str(e))
            
    if st.button('Predict'):
        try:
            st.write('Start predicting')
            predictions = trained_model.predict(X)
            st.write('Computing metricsy')
            cm, cr = compute_metrics(  trained_model, X, y, trained_model.classes_)
            ## plot the results
            
            st.subheader('Confusion Matrix')
            fig = plot_confusion_matrix(cm, ['Normal', 'Attack'])
            st.pyplot(fig)
            
            st.subheader('Classification Report')
            st.write(cr)
            
        except Exception as e:
            st.write(str(e))
    


if __name__ == '__main__':
    main()
    
    