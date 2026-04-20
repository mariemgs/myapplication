export interface Agent {
  name: string;
  icon: string;
  description: string;
  workflow_file: string;
  status: string;
  conclusion: string;
  last_run: string | null;
  last_run_url: string | null;
  run_number: number | null;
}