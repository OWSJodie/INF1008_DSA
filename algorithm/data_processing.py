import ast

import pandas as pd
import numpy as np
from collections import Counter
import algorithm.config as config
import plotly.express as px
import plotly.graph_objects as go
import csv
import algorithm.config as config
import plotly.graph_objs as go
import plotly.io as pio


def load_data(filename):
    """
    Load the data from the csv file.

    Parameters:
    - filename (str): The path to the csv file.

    Returns:
    - df (pandas.DataFrame): The DataFrame containing the data.
    """

    df = pd.read_csv(filename, dtype=str, low_memory=False)
    return df


def map_words_to_values(df, column_name, mapping):
    """
    Map the words in the specified column to values.

    Parameters:
    - df (pandas.DataFrame): The DataFrame containing the data.
    - column_name (str): The name of the column to map.
    - mapping (dict): A dictionary that maps words to values.

    Returns:
    - df (pandas.DataFrame): The DataFrame with the words in the specified column mapped to values.
    """
    df[column_name] = df[column_name].map(mapping)
    return df


def convert_xlsx_to_cleaned_csv(filename, file_location):
    df = pd.read_excel(filename)

    df = map_words_to_values(df, 'Mixed_baseSeverity', config.MAPPING)

    # List of columns you want to modify
    columns_to_modify = ['Mixed_exploitabilityScore',
                         'Mixed_impactScore',
                         'Mixed_baseSeverity',
                         'Mixed_basedScore']

    # Replace non-numeric values with NaN
    for column in columns_to_modify:
        df[column] = pd.to_numeric(df[column], errors='coerce')

    # Replace NaNs with column means in these columns
    for column in columns_to_modify:
        df[column].fillna(df[column].mean(), inplace=True)

    df.to_csv(file_location, index=False)


def convert_xlsx_to_csv(filename, file_location):
    df = pd.read_excel(filename)
    df.to_csv(file_location, index=False)


def calculate_variable_correlations(dataframe, variables_column, list_of_variables):
    """
    Calculates correlations for each variable separately based on the provided DataFrame.

    Parameters:
    - dataframe: The input DataFrame containing the data.
    - variables_column (str): The column name representing the variables.
    - list_of_variables (list): A list of column names representing the variables of interest.

    Returns:
    - correlation_results (dict): A dictionary containing the correlation matrices for each variable.
    """
    correlation_results = {}
    variables = dataframe[variables_column].dropna().unique()

    for variable in variables:
        variable_df = dataframe[dataframe[variables_column] == variable]
        variable_df = variable_df.dropna(subset=list_of_variables)

        correlations = variable_df[list_of_variables].corr()
        average_scores = variable_df[list_of_variables].mean()
        total_num_rows = len(variable_df)

        correlation_results[variable] = {"correlations": correlations,
                                         "average_scores": average_scores,
                                         "total_num_rows": total_num_rows}

    return correlation_results


def calculate_attack_vector_analysis(df):
    """
    Calculate the attack vector analysis based on frequency, mean severity, exploitability score, and impact score.

    Parameters:
    - df (pandas.DataFrame): The DataFrame containing the data.

    Returns:
    - vulnerability_analysis (pandas.DataFrame): The DataFrame containing the attack vector analysis.
    """
    vulnerability_analysis = df.groupby('vulnerability').agg(
        Frequency=pd.NamedAgg(column='vulnerability', aggfunc='count'),
        Mean_Severity=pd.NamedAgg(column='Mixed_baseSeverity', aggfunc='mean'),
        Mean_Exploitability_Score=pd.NamedAgg(column='Mixed_exploitabilityScore', aggfunc='mean'),
        Mean_Impact_Score=pd.NamedAgg(column='Mixed_impactScore', aggfunc='mean')
    ).reset_index()

    return vulnerability_analysis


def calculate_user_interaction(df, vulnerability_analysis):
    """
    Calculate the number of attack vectors that require user interaction.

    Parameters:
    - df (pandas.DataFrame): The DataFrame containing the data.
    - vulnerability_analysis (pandas.DataFrame): The DataFrame containing the attack vector analysis.

    Returns:
    - vulnerability_analysis (pandas.DataFrame): The DataFrame containing the updated attack vector analysis.
    """
    vulnerability_analysis['User_Interaction_Required'] = \
        df[df['cve.metrics.cvssMetricV30.cvssData.userInteraction'] == 'REQUIRED'].groupby('vulnerability')[
            'vulnerability'].count()
    vulnerability_analysis['User_Interaction_Required'].fillna(0, inplace=True)

    return vulnerability_analysis


def get_top_attack_vectors(vulnerability_analysis, top_few):
    """
    Get the top attack vectors based on frequency.

    Parameters:
    - vulnerability_analysis (pandas.DataFrame): The DataFrame containing the attack vector analysis.

    Returns:
    - top_attack_vectors (pandas.DataFrame): The DataFrame containing the top attack vectors.
    """
    top_attack_vectors = vulnerability_analysis.sort_values(by='Frequency', ascending=False).head(top_few)

    return top_attack_vectors


def analyze_attack_vectors(df, top_few):
    """
    Analyze the attack vectors.

    Parameters:
    - df (pandas.DataFrame): The DataFrame containing the data.

    Returns:
    - top_attack_vectors (pandas.DataFrame): The DataFrame containing the top attack vectors.
    """
    vulnerability_analysis = calculate_attack_vector_analysis(df)
    vulnerability_analysis = calculate_user_interaction(df, vulnerability_analysis)
    top_attack_vectors = get_top_attack_vectors(vulnerability_analysis, top_few)
    top_attack_vectors = top_attack_vectors.reset_index(drop=True)

    return top_attack_vectors


def convert_date_column(df, date_column):
    """
    Convert the date column to datetime and resample to get the number of vulnerabilities per month.

    Parameters:
    - df (pandas.DataFrame): The DataFrame containing the data.
    - date_column (str): The name of the date column.

    Returns:
    - df (pandas.DataFrame): The DataFrame with the date column converted to datetime.
    """
    df[date_column] = pd.to_datetime(df[date_column])
    return df


def plot_vulnerabilities_over_time(df, date_column):
    """
    Plot the number of vulnerabilities over time.

    Parameters:
    - df (pandas.DataFrame): The DataFrame containing the data.
    - date_column (str): The name of the date column.
    """
    monthly_vulnerabilities = df.resample('M', on=date_column).size()
    monthly_vulnerabilities.plot()


def count_monthly_vulnerabilities(df, date_column, vulnerability_column, specific_vulnerability=None):
    """
    Count the number of specific vulnerabilities per month. If a specific vulnerability is provided, only count that vulnerability.

    Parameters:
    - df (pandas.DataFrame): The DataFrame containing the data.
    - date_column (str): The name of the date column.
    - vulnerability_column (str): The name of the vulnerability column.
    - specific_vulnerability (str, optional): The name of a specific vulnerability to count.

    Returns:
    - monthly_vulnerabilities (pandas.DataFrame): The DataFrame with the number of specific vulnerabilities per month.
    """
    df_copy = df.copy()  # create a copy of the dataframe
    df_copy[date_column] = pd.to_datetime(df_copy[date_column])
    df_copy.set_index(date_column, inplace=True)
    if specific_vulnerability is not None:
        df_copy = df_copy[df_copy[vulnerability_column] == specific_vulnerability]
    monthly_vulnerabilities = df_copy.groupby([pd.Grouper(freq='M'), vulnerability_column]).size().reset_index()
    monthly_vulnerabilities.columns = [date_column, vulnerability_column, 'Number_of_Vulnerabilities']
    return monthly_vulnerabilities


def count_yearly_vulnerabilities(df, date_column, vulnerability_column, specific_vulnerability=None):
    """
    Count the number of specific vulnerabilities per year. If a specific vulnerability is provided, only count that vulnerability.

    Parameters:
    - df (pandas.DataFrame): The DataFrame containing the data.
    - date_column (str): The name of the date column.
    - vulnerability_column (str): The name of the vulnerability column.
    - specific_vulnerability (str, optional): The name of a specific vulnerability to count.

    Returns:
    - yearly_vulnerabilities (pandas.DataFrame): The DataFrame with the number of specific vulnerabilities per year.
    """
    df_copy = df.copy()  # create a copy of the dataframe
    df_copy[date_column] = pd.to_datetime(df_copy[date_column])
    df_copy.set_index(date_column, inplace=True)
    if specific_vulnerability is not None:
        df_copy = df_copy[df_copy[vulnerability_column] == specific_vulnerability]
    yearly_vulnerabilities = df_copy.groupby([pd.Grouper(freq='Y'), vulnerability_column]).size().reset_index()
    yearly_vulnerabilities.columns = [date_column, vulnerability_column, 'Number_of_Vulnerabilities']
    return yearly_vulnerabilities


def store_vulnerabilities_in_dict(df, vulnerability_column, year):
    """
    Store the DataFrame for each unique vulnerability in a dictionary.

    Parameters:
    - df (pandas.DataFrame): The DataFrame containing the data.
    - vulnerability_column (str): The name of the vulnerability column.
    - year (boolean): True, data will be sorted by year ,else it will be sorted by month .

    Returns:
    - vulnerability_dict (dict): A dictionary where the keys are the vulnerability names and the values are the corresponding DataFrames.
    """
    vulnerabilities = df[vulnerability_column].dropna().unique()
    if year:
        vulnerability_dict = {
            vulnerability: count_yearly_vulnerabilities(df, 'cve.published', vulnerability_column, vulnerability) for
            vulnerability in vulnerabilities}
    else:
        vulnerability_dict = {
            vulnerability: count_monthly_vulnerabilities(df, 'cve.published', vulnerability_column, vulnerability) for
            vulnerability in vulnerabilities}
    return vulnerability_dict


def generate_synthetic_data(df, num_samples=100):
    # Generate synthetic data
    synthetic_data = pd.DataFrame({
        'Mixed_basedScore': np.random.choice(df['Mixed_basedScore'], num_samples),
        'Mixed_exploitabilityScore': np.random.choice(df['Mixed_exploitabilityScore'], num_samples),
        'Mixed_impactScore': np.random.choice(df['Mixed_impactScore'], num_samples),
    })

    return synthetic_data

def analyze_attack_types_time_series(df, frequency='month'):
    """
    Analyze the time series of each unique individual attack.

    Parameters:
    - df (pandas.DataFrame): The DataFrame containing the data.
    - frequency (str): The frequency of the time series, either 'month' or 'year'.

    Returns:
    - traces (list): A list of Plotly line traces for each unique individual attack.
    """

    # Convert the 'cve_published_date' column to the appropriate date format
    df['cve_published_date'] = pd.to_datetime(df['cve_published_date'], format='%d/%m/%Y')

    # Function to clean the attack_type values and extract individual attack types
    def clean_attack_types(types):
        if isinstance(types, str):
            types_list = ast.literal_eval(types)
            cleaned_types = [t.strip('[]\'"') for t in types_list]
            return cleaned_types
        else:
            return []

    # Clean the 'attack_type' column and create a new column with cleaned attack types
    df['cleaned_attack_type'] = df['attack_type'].apply(clean_attack_types)

    # Get unique attack types and concatenate them into a single set
    unique_attack_types_set = set()
    _ = df['cleaned_attack_type'].apply(lambda x: unique_attack_types_set.update(x))

    # Create a list of lin  e traces
    traces = []

    # Create a trace for each unique attack type and add it to the traces list
    for attack_type in unique_attack_types_set:
        df_filtered = df[df['cleaned_attack_type'].apply(lambda x: attack_type in x)]
        if frequency == 'month':
            time_series = df_filtered.groupby(pd.Grouper(key='cve_published_date', freq='M')).size()
        elif frequency == 'year':
            time_series = df_filtered.groupby(pd.Grouper(key='cve_published_date', freq='Y')).size()
        else:
            raise ValueError("Invalid frequency parameter. Use 'month' or 'year'.")

        trace = go.Scatter(
            x=time_series.index,
            y=time_series.values,
            mode='lines',
            name=attack_type
        )
        traces.append(trace)

        layout = go.Layout(
            title='Number of Vulnerabilities over Time',
            xaxis=dict(title='Date', automargin=True),
            yaxis=dict(title='Number of Vulnerabilities', automargin=True),
            showlegend=True,
        )

        # Create the figure
        fig = go.Figure(data=traces, layout=layout)


    return fig

def analyze_attack_types_by_vendor(df):
    """
    Analyze the attack types by vendor.

    Parameters:
    - df (pandas.DataFrame): The DataFrame containing the data.

    Returns:
    - fig (plotly.graph_objects.Figure): The figure containing the plot.
    """

    # Convert the 'cve_published_date' column to the appropriate date format
    df['cve_published_date'] = pd.to_datetime(df['cve_published_date'], format='%d/%m/%Y')

    # Function to clean the attack_type values and extract individual attack types
    def clean_attack_types(types):
        if isinstance(types, str):
            types_list = ast.literal_eval(types)
            cleaned_types = [t.strip('[]\'"') for t in types_list]
            return cleaned_types
        else:
            return []

    # Clean the 'attack_type' column and create a new column with cleaned attack types
    df['cleaned_attack_type'] = df['attack_type'].apply(clean_attack_types)

    # Get unique attack types and concatenate them into a single set
    unique_attack_types_set = set()
    _ = df['cleaned_attack_type'].apply(lambda x: unique_attack_types_set.update(x))

    # Get unique vendors
    unique_vendors = df['vendor'].unique()

    # Create the layout
    layout = go.Layout(
        title='CVEs Time Series for Different Attacks by Vendor',
        xaxis=dict(title='Date', automargin=True),
        yaxis=dict(title='Vendor', automargin=True),
        showlegend=True,
    )

    # Create the figure
    fig = go.Figure(layout=layout)

    # Create a trace for each unique attack type and add it to the figure
    for attack_type in unique_attack_types_set:
        df_filtered = df[df['cleaned_attack_type'].apply(lambda x: attack_type in x)]
        fig.add_trace(go.Scatter(
            x=df_filtered['cve_published_date'],
            y=df_filtered['vendor'],
            mode='markers',
            marker=dict(size=8, opacity=0.7),
            name=attack_type
        ))

    # Return the figure
    return fig

def count_countries_by_year_range(filename, start_year, end_year):
    with open(filename, 'r', newline='') as csvfile:
        reader = csv.reader(csvfile)
        header = next(reader)  # Read the header row


        date_index = header.index('Year')
        country_index = header.index('Country')

        year_country_counts = {}

        for row in reader:
            date = row[date_index]
            year = date.split('-')[0]  # Extract the year from the date

            if start_year <= year <= end_year:
                country = row[country_index]
                if year in year_country_counts:
                    if country in year_country_counts[year]:
                        year_country_counts[year][country] += 1
                    else:
                        year_country_counts[year][country] = 1
                else:
                    year_country_counts[year] = {country: 1}

        return year_country_counts

def plot_ransomware_attacks(result):
    # Convert the result into a DataFrame
    df = pd.DataFrame(result).T
    df_sorted = df.sort_index(ascending=False)

    # Create a plotly figure
    fig = go.Figure()

    # Add a bar for each country
    for country in df_sorted.columns:
        fig.add_trace(
            go.Bar(
                x=df_sorted.index,
                y=df_sorted[country],
                name=country
            )
        )

    # Update layout
    fig.update_layout(
        title="Ransomware Attacks over the Years by Countries",
        xaxis_title="Year",
        yaxis_title="Number of Ransomware Attacks",
        barmode='stack'
    )

    # Show the figure
    return fig


# file_location = '../dataset/updated_cve_2023_07_09.xlsx'
# csv_file_location = '../dataset/updated_cve_2023_07_09.csv'
# convert_xlsx_to_cleaned_csv(file_location,csv_file_location)


