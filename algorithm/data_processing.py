import pandas as pd
import numpy as np
import algorithm.config as config


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


def convert_xlsx_to_cleaned_csv(filename, file_location):
    df = pd.read_excel(filename)

    # List of columns you want to modify
    columns_to_modify = ['Mixed_exploitabilityScore',
                         'Mixed_impactScore',
                         'Mixed_baseSeverity',
                         'Mixed_basedScore']

    # Replace zeros with NaNs in these columns
    for column in columns_to_modify:
        df[column].replace(0, np.nan, inplace=True)

    # Replace NaNs with column means in these columns
    for column in columns_to_modify:
        df[column].fillna(df[column].mean(), inplace=True)

    df.to_csv(file_location, index=False)


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


def generate_synthetic_data(df,num_samples=100):
    # Generate synthetic data
    synthetic_data = pd.DataFrame({
        'Mixed_basedScore': np.random.choice(df['Mixed_basedScore'], num_samples),
        'Mixed_exploitabilityScore': np.random.choice(df['Mixed_exploitabilityScore'], num_samples),
        'Mixed_impactScore': np.random.choice(df['Mixed_impactScore'], num_samples),
    })

    return synthetic_data