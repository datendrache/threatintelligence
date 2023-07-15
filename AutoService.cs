using System;
using System.Diagnostics;
using System.ServiceProcess;
using System.Threading;

namespace ThreatIntelligence
{
    public partial class AutoService : ServiceBase
    {
        Thread serverThread = null;

        public AutoService()
        {

        }

        protected override void OnStart(string[] args)
        {
            try
            {
                serverThread = new System.Threading.Thread(StartProcess);
                serverThread.IsBackground = true;
                serverThread.Start();
            }
            catch (Exception xyz)
            {

            }
        }

        private void StartProcess()
        {
            string connectionstring = "Server=localhost;Database=Archlake;User Id=sa;Password=1jp4pwthnbhy!;";

            int currenthour = 0;
            Boolean ThreatIntelligenceFeedCollectionToday = false;

            while (true)
            {
                if (currenthour != DateTime.Now.Hour)
                {
                    if (DateTime.Now.Hour==23)
                    {
                        // End of the day, time to reset all batch jobs

                        ThreatIntelligenceFeedCollectionToday = false;
                    }

                    if (DateTime.Now.Hour==1)
                    {
                        if (!ThreatIntelligenceFeedCollectionToday)
                        {
                            ThreatIntelligenceFeedCollectionToday = true;
                            try
                            {
                                
                            }
                            catch (Exception xyz)
                            {

                            }
                        }                      
                    }
                }
                Thread.Sleep(10000);
            }
        }

        protected override void OnStop()
        {
            Process.GetCurrentProcess().Kill();
        }
    }
}
