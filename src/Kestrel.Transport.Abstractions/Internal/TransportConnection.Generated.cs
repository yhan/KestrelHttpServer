// Copyright (c) .NET Foundation. All rights reserved.
// Licensed under the Apache License, Version 2.0. See License.txt in the project root for license information.

using System;
using System.Collections;
using System.Collections.Generic;

using Microsoft.AspNetCore.Connections.Features;
using Microsoft.AspNetCore.Http.Features;

namespace Microsoft.AspNetCore.Server.Kestrel.Transport.Abstractions.Internal
{
    public partial class TransportConnection : IFeatureCollection
    {
        private static readonly Type IHttpConnectionFeatureType = typeof(IHttpConnectionFeature);
        private static readonly Type IConnectionIdFeatureType = typeof(IConnectionIdFeature);
        private static readonly Type IConnectionTransportFeatureType = typeof(IConnectionTransportFeature);
        private static readonly Type IConnectionItemsFeatureType = typeof(IConnectionItemsFeature);
        private static readonly Type IMemoryPoolFeatureType = typeof(IMemoryPoolFeature);
        private static readonly Type IApplicationTransportFeatureType = typeof(IApplicationTransportFeature);
        private static readonly Type ITransportSchedulerFeatureType = typeof(ITransportSchedulerFeature);
        private static readonly Type IConnectionLifetimeFeatureType = typeof(IConnectionLifetimeFeature);
        private static readonly Type IConnectionHeartbeatTickFeatureType = typeof(IConnectionHeartbeatTickFeature);
        private static readonly Type IConnectionLifetimeNotificationFeatureType = typeof(IConnectionLifetimeNotificationFeature);
        private static readonly Type IBytesWrittenFeatureType = typeof(IBytesWrittenFeature);

        private object _currentIHttpConnectionFeature;
        private object _currentIConnectionIdFeature;
        private object _currentIConnectionTransportFeature;
        private object _currentIConnectionItemsFeature;
        private object _currentIMemoryPoolFeature;
        private object _currentIApplicationTransportFeature;
        private object _currentITransportSchedulerFeature;
        private object _currentIConnectionLifetimeFeature;
        private object _currentIConnectionHeartbeatTickFeature;
        private object _currentIConnectionLifetimeNotificationFeature;
        private object _currentIBytesWrittenFeature;

        private int _featureRevision;

        private List<KeyValuePair<Type, object>> MaybeExtra;

        private void FastReset()
        {
            _currentIHttpConnectionFeature = this;
            _currentIConnectionIdFeature = this;
            _currentIConnectionTransportFeature = this;
            _currentIConnectionItemsFeature = this;
            _currentIMemoryPoolFeature = this;
            _currentIApplicationTransportFeature = this;
            _currentITransportSchedulerFeature = this;
            _currentIConnectionLifetimeFeature = this;
            _currentIConnectionHeartbeatTickFeature = this;
            _currentIConnectionLifetimeNotificationFeature = this;
            _currentIBytesWrittenFeature = this;

        }

        // Internal for testing
        internal void ResetFeatureCollection()
        {
            FastReset();
            MaybeExtra?.Clear();
            _featureRevision++;
        }

        private object ExtraFeatureGet(Type key)
        {
            if (MaybeExtra == null)
            {
                return null;
            }
            for (var i = 0; i < MaybeExtra.Count; i++)
            {
                var kv = MaybeExtra[i];
                if (kv.Key == key)
                {
                    return kv.Value;
                }
            }
            return null;
        }

        private void ExtraFeatureSet(Type key, object value)
        {
            if (MaybeExtra == null)
            {
                MaybeExtra = new List<KeyValuePair<Type, object>>(2);
            }

            for (var i = 0; i < MaybeExtra.Count; i++)
            {
                if (MaybeExtra[i].Key == key)
                {
                    MaybeExtra[i] = new KeyValuePair<Type, object>(key, value);
                    return;
                }
            }
            MaybeExtra.Add(new KeyValuePair<Type, object>(key, value));
        }

        bool IFeatureCollection.IsReadOnly => false;

        int IFeatureCollection.Revision => _featureRevision;

        object IFeatureCollection.this[Type key]
        {
            get
            {
                object feature = null;
                if (key == IHttpConnectionFeatureType)
                {
                    feature = _currentIHttpConnectionFeature;
                }
                else if (key == IConnectionIdFeatureType)
                {
                    feature = _currentIConnectionIdFeature;
                }
                else if (key == IConnectionTransportFeatureType)
                {
                    feature = _currentIConnectionTransportFeature;
                }
                else if (key == IConnectionItemsFeatureType)
                {
                    feature = _currentIConnectionItemsFeature;
                }
                else if (key == IMemoryPoolFeatureType)
                {
                    feature = _currentIMemoryPoolFeature;
                }
                else if (key == IApplicationTransportFeatureType)
                {
                    feature = _currentIApplicationTransportFeature;
                }
                else if (key == ITransportSchedulerFeatureType)
                {
                    feature = _currentITransportSchedulerFeature;
                }
                else if (key == IConnectionLifetimeFeatureType)
                {
                    feature = _currentIConnectionLifetimeFeature;
                }
                else if (key == IConnectionHeartbeatTickFeatureType)
                {
                    feature = _currentIConnectionHeartbeatTickFeature;
                }
                else if (key == IConnectionLifetimeNotificationFeatureType)
                {
                    feature = _currentIConnectionLifetimeNotificationFeature;
                }
                else if (key == IBytesWrittenFeatureType)
                {
                    feature = _currentIBytesWrittenFeature;
                }
                else if (MaybeExtra != null)
                {
                    feature = ExtraFeatureGet(key);
                }

                return feature;
            }

            set
            {
                _featureRevision++;

                if (key == IHttpConnectionFeatureType)
                {
                    _currentIHttpConnectionFeature = value;
                }
                else if (key == IConnectionIdFeatureType)
                {
                    _currentIConnectionIdFeature = value;
                }
                else if (key == IConnectionTransportFeatureType)
                {
                    _currentIConnectionTransportFeature = value;
                }
                else if (key == IConnectionItemsFeatureType)
                {
                    _currentIConnectionItemsFeature = value;
                }
                else if (key == IMemoryPoolFeatureType)
                {
                    _currentIMemoryPoolFeature = value;
                }
                else if (key == IApplicationTransportFeatureType)
                {
                    _currentIApplicationTransportFeature = value;
                }
                else if (key == ITransportSchedulerFeatureType)
                {
                    _currentITransportSchedulerFeature = value;
                }
                else if (key == IConnectionLifetimeFeatureType)
                {
                    _currentIConnectionLifetimeFeature = value;
                }
                else if (key == IConnectionHeartbeatTickFeatureType)
                {
                    _currentIConnectionHeartbeatTickFeature = value;
                }
                else if (key == IConnectionLifetimeNotificationFeatureType)
                {
                    _currentIConnectionLifetimeNotificationFeature = value;
                }
                else if (key == IBytesWrittenFeatureType)
                {
                    _currentIBytesWrittenFeature = value;
                }
                else
                {
                    ExtraFeatureSet(key, value);
                }
            }
        }

        TFeature IFeatureCollection.Get<TFeature>()
        {
            TFeature feature = default;
            if (typeof(TFeature) == typeof(IHttpConnectionFeature))
            {
                feature = (TFeature)_currentIHttpConnectionFeature;
            }
            else if (typeof(TFeature) == typeof(IConnectionIdFeature))
            {
                feature = (TFeature)_currentIConnectionIdFeature;
            }
            else if (typeof(TFeature) == typeof(IConnectionTransportFeature))
            {
                feature = (TFeature)_currentIConnectionTransportFeature;
            }
            else if (typeof(TFeature) == typeof(IConnectionItemsFeature))
            {
                feature = (TFeature)_currentIConnectionItemsFeature;
            }
            else if (typeof(TFeature) == typeof(IMemoryPoolFeature))
            {
                feature = (TFeature)_currentIMemoryPoolFeature;
            }
            else if (typeof(TFeature) == typeof(IApplicationTransportFeature))
            {
                feature = (TFeature)_currentIApplicationTransportFeature;
            }
            else if (typeof(TFeature) == typeof(ITransportSchedulerFeature))
            {
                feature = (TFeature)_currentITransportSchedulerFeature;
            }
            else if (typeof(TFeature) == typeof(IConnectionLifetimeFeature))
            {
                feature = (TFeature)_currentIConnectionLifetimeFeature;
            }
            else if (typeof(TFeature) == typeof(IConnectionHeartbeatTickFeature))
            {
                feature = (TFeature)_currentIConnectionHeartbeatTickFeature;
            }
            else if (typeof(TFeature) == typeof(IConnectionLifetimeNotificationFeature))
            {
                feature = (TFeature)_currentIConnectionLifetimeNotificationFeature;
            }
            else if (typeof(TFeature) == typeof(IBytesWrittenFeature))
            {
                feature = (TFeature)_currentIBytesWrittenFeature;
            }
            else if (MaybeExtra != null)
            {
                feature = (TFeature)(ExtraFeatureGet(typeof(TFeature)));
            }

            return feature;
        }

        void IFeatureCollection.Set<TFeature>(TFeature feature)
        {
            _featureRevision++;
            if (typeof(TFeature) == typeof(IHttpConnectionFeature))
            {
                _currentIHttpConnectionFeature = feature;
            }
            else if (typeof(TFeature) == typeof(IConnectionIdFeature))
            {
                _currentIConnectionIdFeature = feature;
            }
            else if (typeof(TFeature) == typeof(IConnectionTransportFeature))
            {
                _currentIConnectionTransportFeature = feature;
            }
            else if (typeof(TFeature) == typeof(IConnectionItemsFeature))
            {
                _currentIConnectionItemsFeature = feature;
            }
            else if (typeof(TFeature) == typeof(IMemoryPoolFeature))
            {
                _currentIMemoryPoolFeature = feature;
            }
            else if (typeof(TFeature) == typeof(IApplicationTransportFeature))
            {
                _currentIApplicationTransportFeature = feature;
            }
            else if (typeof(TFeature) == typeof(ITransportSchedulerFeature))
            {
                _currentITransportSchedulerFeature = feature;
            }
            else if (typeof(TFeature) == typeof(IConnectionLifetimeFeature))
            {
                _currentIConnectionLifetimeFeature = feature;
            }
            else if (typeof(TFeature) == typeof(IConnectionHeartbeatTickFeature))
            {
                _currentIConnectionHeartbeatTickFeature = feature;
            }
            else if (typeof(TFeature) == typeof(IConnectionLifetimeNotificationFeature))
            {
                _currentIConnectionLifetimeNotificationFeature = feature;
            }
            else if (typeof(TFeature) == typeof(IBytesWrittenFeature))
            {
                _currentIBytesWrittenFeature = feature;
            }
            else
            {
                ExtraFeatureSet(typeof(TFeature), feature);
            }
        }

        private IEnumerable<KeyValuePair<Type, object>> FastEnumerable()
        {
            if (_currentIHttpConnectionFeature != null)
            {
                yield return new KeyValuePair<Type, object>(IHttpConnectionFeatureType, _currentIHttpConnectionFeature);
            }
            if (_currentIConnectionIdFeature != null)
            {
                yield return new KeyValuePair<Type, object>(IConnectionIdFeatureType, _currentIConnectionIdFeature);
            }
            if (_currentIConnectionTransportFeature != null)
            {
                yield return new KeyValuePair<Type, object>(IConnectionTransportFeatureType, _currentIConnectionTransportFeature);
            }
            if (_currentIConnectionItemsFeature != null)
            {
                yield return new KeyValuePair<Type, object>(IConnectionItemsFeatureType, _currentIConnectionItemsFeature);
            }
            if (_currentIMemoryPoolFeature != null)
            {
                yield return new KeyValuePair<Type, object>(IMemoryPoolFeatureType, _currentIMemoryPoolFeature);
            }
            if (_currentIApplicationTransportFeature != null)
            {
                yield return new KeyValuePair<Type, object>(IApplicationTransportFeatureType, _currentIApplicationTransportFeature);
            }
            if (_currentITransportSchedulerFeature != null)
            {
                yield return new KeyValuePair<Type, object>(ITransportSchedulerFeatureType, _currentITransportSchedulerFeature);
            }
            if (_currentIConnectionLifetimeFeature != null)
            {
                yield return new KeyValuePair<Type, object>(IConnectionLifetimeFeatureType, _currentIConnectionLifetimeFeature);
            }
            if (_currentIConnectionHeartbeatTickFeature != null)
            {
                yield return new KeyValuePair<Type, object>(IConnectionHeartbeatTickFeatureType, _currentIConnectionHeartbeatTickFeature);
            }
            if (_currentIConnectionLifetimeNotificationFeature != null)
            {
                yield return new KeyValuePair<Type, object>(IConnectionLifetimeNotificationFeatureType, _currentIConnectionLifetimeNotificationFeature);
            }
            if (_currentIBytesWrittenFeature != null)
            {
                yield return new KeyValuePair<Type, object>(IBytesWrittenFeatureType, _currentIBytesWrittenFeature);
            }

            if (MaybeExtra != null)
            {
                foreach (var item in MaybeExtra)
                {
                    yield return item;
                }
            }
        }

        IEnumerator<KeyValuePair<Type, object>> IEnumerable<KeyValuePair<Type, object>>.GetEnumerator() => FastEnumerable().GetEnumerator();

        IEnumerator IEnumerable.GetEnumerator() => FastEnumerable().GetEnumerator();
    }
}
