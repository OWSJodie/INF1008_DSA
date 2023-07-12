import pandas as pd


def load_data(filename):
    """
    Load the data from the Excel file.

    Parameters:
    - filename (str): The path to the Excel file.

    Returns:
    - df (pandas.DataFrame): The DataFrame containing the data.
    """
    df = pd.read_excel(filename)
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


def main():  # run this py module will run main function code
    pd.set_option('display.max_rows', None)
    pd.set_option('display.max_columns', None)
    file_location = '../dataset/updated_cve_2023_07_09.xlsx'

    mapping = {
        'LOW': 2.5,
        'MEDIUM': 5,
        'HIGH': 7.5,
        'CRITICAL': 10
    }

    variables_of_interest = ['Mixed_exploitabilityScore',
                             'Mixed_impactScore',
                             'Mixed_baseSeverity',
                             'Mixed_basedScore']

    df = load_data(file_location)
    df = map_words_to_values(df, 'Mixed_baseSeverity', mapping)
    filtered_df = df[(df[variables_of_interest] != 0).dropna().all(axis=1)]
    correlations = calculate_variable_correlations(filtered_df, 'vulnerability', variables_of_interest)

    top_attack_vectors = analyze_attack_vectors(df, 5)

    print("Correlations:")
    print(correlations)
    print("Top Attack Vectors:")
    print(top_attack_vectors)


if __name__ == '__main__':
    main()
