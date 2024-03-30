namespace FBI
{
    public class NetworkAdapterInfo
    {
        public NetworkAdapterInfo(string name, string ip)
        {
            Name = name;
            IP = ip;
        }

        public string Name { get; private set; }

        public string IP { get; private set; }

        public override string ToString() => $"{Name} - ({IP})";
    }
}